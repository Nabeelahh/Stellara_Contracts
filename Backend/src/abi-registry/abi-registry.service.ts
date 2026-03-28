import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import {
  DecodeContractResultDto,
  ParseContractEventDto,
  PrepareInvocationDto,
  UpsertAbiRegistryDto,
} from './dto/abi-registry.dto';

import { PrismaService } from '../prisma.service';

type JsonObject = Record<string, any>;

interface ResolvedAbiVersion {
  registry: any;
  version: any;
}

@Injectable()
export class AbiRegistryService {
  constructor(private readonly prisma: PrismaService) { }

  async listRegistries () {
    const registries = await this.prisma.contractAbiRegistry.findMany({
      include: {
        versions: {
          orderBy: { createdAt: 'desc' },
        },
      },
      orderBy: { updatedAt: 'desc' },
    });

    return registries.map((registry) => ({
      id: registry.id,
      contractAddress: registry.contractAddress,
      contractType: registry.contractType,
      displayName: registry.displayName,
      network: registry.network,
      description: registry.description,
      currentVersion:
        registry.currentVersion ??
        registry.versions.find((version) => version.isCurrent)?.version ??
        registry.versions[0]?.version,
      version: (() => {
        const activeVersion =
          registry.versions.find((entry) => entry.version === registry.currentVersion) ||
          registry.versions.find((entry) => entry.isCurrent) ||
          registry.versions[0];

        return activeVersion
          ? {
            id: activeVersion.id,
            version: activeVersion.version,
            isCurrent: activeVersion.isCurrent,
            isDeprecated: activeVersion.isDeprecated,
            abiSchema: activeVersion.abiSchema,
            contractSchema: activeVersion.contractSchema,
            functionSchemas: activeVersion.functionSchemas,
            eventSchemas: activeVersion.eventSchemas,
            changelog: activeVersion.changelog,
          }
          : null;
      })(),
      versions: registry.versions.map((version) => ({
        id: version.id,
        version: version.version,
        isCurrent: version.isCurrent,
        isDeprecated: version.isDeprecated,
        changelog: version.changelog,
        createdAt: version.createdAt,
      })),
    }));
  }

  async getRegistry (contractAddress: string, version?: string) {
    const resolved = await this.resolveRegistryVersion(contractAddress, version);
    return this.toRegistryResponse(resolved);
  }

  async upsertRegistry (actorId: string | undefined, dto: UpsertAbiRegistryDto) {
    this.validateSchemaPayload(dto);

    const markAsCurrent = dto.markAsCurrent !== false;
    const existingRegistry = await this.prisma.contractAbiRegistry.findUnique({
      where: { contractAddress: dto.contractAddress },
      include: { versions: true },
    });

    const registry = existingRegistry
      ? await this.prisma.contractAbiRegistry.update({
        where: { contractAddress: dto.contractAddress },
        data: {
          contractType: dto.contractType,
          displayName: dto.displayName,
          description: dto.description,
          network: dto.network ?? existingRegistry.network,
          metadata: (dto.metadata as never) ?? existingRegistry.metadata ?? undefined,
          updatedBy: actorId,
          ...(markAsCurrent ? { currentVersion: dto.version } : {}),
        },
      })
      : await this.prisma.contractAbiRegistry.create({
        data: {
          contractAddress: dto.contractAddress,
          contractType: dto.contractType,
          displayName: dto.displayName as never,
          description: dto.description as never,
          network: dto.network ?? 'stellar',
          metadata: dto.metadata as never,
          createdBy: actorId,
          updatedBy: actorId,
          currentVersion: markAsCurrent ? dto.version : null,
        },
      });

    const existingVersion = await this.prisma.contractAbiVersion.findFirst({
      where: {
        registryId: registry.id,
        version: dto.version,
      },
    });

    if (markAsCurrent) {
      await this.prisma.contractAbiVersion.updateMany({
        where: { registryId: registry.id },
        data: { isCurrent: false },
      });
    }

    const versionRecord = existingVersion
      ? await this.prisma.contractAbiVersion.update({
        where: { id: existingVersion.id },
        data: {
          abiSchema: dto.abiSchema as never,
          contractSchema: dto.contractSchema as never,
          functionSchemas: this.normalizeFunctionSchemas(dto),
          eventSchemas: this.normalizeEventSchemas(dto),
          compatibility: dto.compatibility as never,
          changelog: dto.changelog,
          createdBy: actorId ?? existingVersion.createdBy,
          isCurrent: markAsCurrent,
        },
      })
      : await this.prisma.contractAbiVersion.create({
        data: {
          registryId: registry.id,
          version: dto.version,
          abiSchema: dto.abiSchema as never,
          contractSchema: dto.contractSchema as never,
          functionSchemas: this.normalizeFunctionSchemas(dto),
          eventSchemas: this.normalizeEventSchemas(dto),
          compatibility: dto.compatibility as never,
          changelog: dto.changelog,
          createdBy: actorId,
          isCurrent: markAsCurrent,
        },
      });

    return this.toRegistryResponse({
      registry,
      version: versionRecord,
    });
  }

  async prepareInvocation (contractAddress: string, dto: PrepareInvocationDto) {
    const resolved = await this.resolveRegistryVersion(contractAddress, dto.version);
    const functionSchema = this.getFunctionSchema(resolved.version, dto.functionName);
    const argumentMap = Object.fromEntries(
      dto.arguments.map((argument) => [argument.name, argument.value]),
    );

    const normalizedArgs = (functionSchema.inputs ?? []).map((input: any, index: number) => {
      const value =
        argumentMap[input.name] !== undefined
          ? argumentMap[input.name]
          : dto.arguments[index]?.value;

      this.validateAgainstTypeDescriptor(value, input, input.name);

      return {
        name: input.name,
        type: input.type,
        value,
      };
    });

    return {
      contractAddress,
      contractType: resolved.registry.contractType,
      version: resolved.version.version,
      functionName: dto.functionName,
      arguments: normalizedArgs,
      returns: functionSchema.outputs ?? [],
    };
  }

  async decodeContractResult (contractAddress: string, dto: DecodeContractResultDto) {
    const resolved = await this.resolveRegistryVersion(contractAddress, dto.version);
    const functionSchema = this.getFunctionSchema(resolved.version, dto.functionName);
    const outputs = functionSchema.outputs ?? [];
    const rawValues = Array.isArray(dto.rawResult) ? dto.rawResult : [dto.rawResult];

    const decoded = outputs.map((output: any, index: number) => ({
      name: output.name ?? `result${index}`,
      type: output.type,
      value: this.decodeValue(rawValues[index], output),
    }));

    return {
      contractAddress,
      contractType: resolved.registry.contractType,
      version: resolved.version.version,
      functionName: dto.functionName,
      decoded,
      result:
        decoded.length === 1
          ? decoded[0].value
          : Object.fromEntries(decoded.map((entry) => [entry.name, entry.value])),
    };
  }

  async parseContractEvent (contractAddress: string, dto: ParseContractEventDto) {
    const resolved = await this.resolveRegistryVersion(contractAddress, dto.version);
    const eventName = dto.eventName || this.deriveEventName(dto.topics, dto.data);
    const eventSchema = this.getEventSchema(resolved.version, eventName);
    const payload = this.normalizePayload(dto.data);

    const decodedEntries = Object.entries(eventSchema.fields ?? {}).map(
      ([fieldName, descriptor]) => [fieldName, this.decodeValue(payload[fieldName], descriptor)],
    );

    return {
      contractAddress,
      contractType: resolved.registry.contractType,
      version: resolved.version.version,
      eventName,
      decoded: Object.fromEntries(decodedEntries),
      schema: eventSchema,
    };
  }

  async parseIndexedEvent (event: {
    contractId: string;
    topic?: string[];
    data?: unknown;
    eventName?: string;
  }) {
    return this.parseContractEvent(event.contractId, {
      topics: event.topic,
      data: event.data,
      eventName: event.eventName,
    });
  }

  private async resolveRegistryVersion (
    contractAddress: string,
    version?: string,
  ): Promise<ResolvedAbiVersion> {
    const registry = await this.prisma.contractAbiRegistry.findUnique({
      where: { contractAddress },
      include: {
        versions: {
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!registry) {
      throw new NotFoundException(`ABI registry not found for ${contractAddress}`);
    }

    const resolvedVersion =
      registry.versions.find((entry) => entry.version === version) ||
      registry.versions.find((entry) => entry.isCurrent) ||
      registry.versions.sort((left, right) => this.compareVersions(right.version, left.version))[0];

    if (!resolvedVersion) {
      throw new NotFoundException(`No ABI versions registered for ${contractAddress}`);
    }

    return { registry, version: resolvedVersion };
  }

  private getFunctionSchema (version: any, functionName: string): JsonObject {
    const functions = (version.functionSchemas ?? {}) as JsonObject;
    const schema = functions[functionName];

    if (!schema) {
      throw new NotFoundException(
        `Function ${functionName} is not defined in ABI version ${version.version}`,
      );
    }

    return schema;
  }

  private getEventSchema (version: any, eventName: string): JsonObject {
    const events = (version.eventSchemas ?? {}) as JsonObject;
    const schema = events[eventName];

    if (!schema) {
      throw new NotFoundException(
        `Event ${eventName} is not defined in ABI version ${version.version}`,
      );
    }

    return schema;
  }

  private normalizeFunctionSchemas (dto: UpsertAbiRegistryDto): JsonObject {
    if (dto.functionSchemas && Object.keys(dto.functionSchemas).length > 0) {
      return dto.functionSchemas as JsonObject;
    }

    return this.extractSchemasFromAbi(dto.abiSchema, 'function');
  }

  private normalizeEventSchemas (dto: UpsertAbiRegistryDto): JsonObject {
    if (dto.eventSchemas && Object.keys(dto.eventSchemas).length > 0) {
      return dto.eventSchemas as JsonObject;
    }

    return this.extractSchemasFromAbi(dto.abiSchema, 'event');
  }

  private extractSchemasFromAbi (abiSchema: Record<string, unknown>, kind: 'function' | 'event') {
    const entries = Array.isArray((abiSchema as any)?.spec?.entries)
      ? ((abiSchema as any).spec.entries as JsonObject[])
      : [];

    return entries.reduce<JsonObject>((accumulator, entry) => {
      if (entry.type !== kind || !entry.name) {
        return accumulator;
      }

      accumulator[String(entry.name)] = {
        name: entry.name,
        inputs: entry.inputs ?? [],
        outputs: entry.outputs ?? [],
        fields: entry.fields ?? {},
        doc: entry.doc ?? '',
      };
      return accumulator;
    }, {});
  }

  private validateSchemaPayload (dto: UpsertAbiRegistryDto): void {
    const functionSchemas = this.normalizeFunctionSchemas(dto);
    const eventSchemas = this.normalizeEventSchemas(dto);

    if (!Object.keys(functionSchemas).length) {
      throw new BadRequestException('ABI payload must define at least one function schema.');
    }

    if (!dto.contractSchema || typeof dto.contractSchema !== 'object') {
      throw new BadRequestException('A JSON schema for the contract type is required.');
    }

    if (!Object.keys(eventSchemas).length) {
      throw new BadRequestException('ABI payload must define at least one event schema.');
    }
  }

  private toRegistryResponse (resolved: ResolvedAbiVersion) {
    return {
      id: resolved.registry.id,
      contractAddress: resolved.registry.contractAddress,
      contractType: resolved.registry.contractType,
      displayName: resolved.registry.displayName,
      network: resolved.registry.network,
      description: resolved.registry.description,
      currentVersion: resolved.registry.currentVersion ?? resolved.version.version,
      version: {
        id: resolved.version.id,
        version: resolved.version.version,
        isCurrent: resolved.version.isCurrent,
        isDeprecated: resolved.version.isDeprecated,
        abiSchema: resolved.version.abiSchema,
        contractSchema: resolved.version.contractSchema,
        functionSchemas: resolved.version.functionSchemas,
        eventSchemas: resolved.version.eventSchemas,
        compatibility: resolved.version.compatibility,
        changelog: resolved.version.changelog,
      },
    };
  }

  private compareVersions (left: string, right: string): number {
    const leftParts = left.split('.').map((part) => Number(part) || 0);
    const rightParts = right.split('.').map((part) => Number(part) || 0);
    const length = Math.max(leftParts.length, rightParts.length);

    for (let index = 0; index < length; index += 1) {
      const diff = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
      if (diff !== 0) {
        return diff;
      }
    }

    return 0;
  }

  private deriveEventName (topics?: string[], data?: unknown): string {
    if (topics?.length) {
      try {
        return Buffer.from(topics[0], 'base64').toString('utf8') || topics[0];
      } catch {
        return topics[0];
      }
    }

    const payload = this.normalizePayload(data);
    return String(payload.eventName ?? payload.name ?? 'unknown');
  }

  private normalizePayload (data: unknown): JsonObject {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      return data as JsonObject;
    }

    if (typeof data === 'string') {
      try {
        const parsed = JSON.parse(data);
        return parsed && typeof parsed === 'object' ? parsed : { value: parsed };
      } catch {
        return { value: data };
      }
    }

    return { value: data };
  }

  private decodeValue (value: unknown, descriptor: any): unknown {
    const typeName = String(descriptor?.type ?? descriptor ?? 'string').toLowerCase();

    if (value === null || value === undefined) {
      return value;
    }

    if (typeName === 'bool' || typeName === 'boolean') {
      return Boolean(value);
    }

    if (
      typeName === 'u32' ||
      typeName === 'u64' ||
      typeName === 'u128' ||
      typeName === 'i32' ||
      typeName === 'i64' ||
      typeName === 'i128' ||
      typeName === 'number' ||
      typeName === 'int'
    ) {
      const normalized = typeof value === 'string' ? Number(value) : value;
      return typeof normalized === 'number' && Number.isFinite(normalized) ? normalized : value;
    }

    if (typeName === 'array' && Array.isArray(value)) {
      const itemDescriptor = descriptor.items ?? { type: 'string' };
      return value.map((item) => this.decodeValue(item, itemDescriptor));
    }

    if (
      (typeName === 'object' || typeName === 'struct' || descriptor.fields) &&
      value &&
      typeof value === 'object'
    ) {
      const fields = descriptor.fields ?? {};
      return Object.entries(value as JsonObject).reduce<JsonObject>(
        (accumulator, [key, fieldValue]) => {
          accumulator[key] = this.decodeValue(fieldValue, fields[key] ?? { type: 'string' });
          return accumulator;
        },
        {},
      );
    }

    return value;
  }

  private validateAgainstTypeDescriptor (value: unknown, descriptor: any, fieldName: string): void {
    const typeName = String(descriptor?.type ?? descriptor ?? 'string').toLowerCase();

    if (value === undefined || value === null) {
      throw new BadRequestException(`Missing required argument ${fieldName}.`);
    }

    if ((typeName === 'bool' || typeName === 'boolean') && typeof value !== 'boolean') {
      throw new BadRequestException(`Argument ${fieldName} must be a boolean.`);
    }

    if (
      ['u32', 'u64', 'u128', 'i32', 'i64', 'i128', 'number', 'int'].includes(typeName) &&
      !(typeof value === 'number' || (typeof value === 'string' && value.trim() !== ''))
    ) {
      throw new BadRequestException(`Argument ${fieldName} must be numeric.`);
    }

    if (typeName === 'array' && !Array.isArray(value)) {
      throw new BadRequestException(`Argument ${fieldName} must be an array.`);
    }

    if (
      (typeName === 'object' || typeName === 'struct') &&
      (typeof value !== 'object' || Array.isArray(value))
    ) {
      throw new BadRequestException(`Argument ${fieldName} must be an object.`);
    }
  }
}
