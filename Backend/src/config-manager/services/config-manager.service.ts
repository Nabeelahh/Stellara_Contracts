import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma.service';
import { SecretsService } from './secrets.service';
import { ConfigAuditService } from './config-audit.service';
import { ConfigScope } from '../interfaces/config.interfaces';
import { SetConfigDto } from '../dto/config.dto';

/**
 * Hierarchical config resolution: env → global DB → tenant DB → user DB
 * Secrets stored in AWS Secrets Manager are fetched transparently when encrypted=true.
 */
@Injectable()
export class ConfigManagerService {
  private readonly logger = new Logger(ConfigManagerService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly secrets: SecretsService,
    private readonly audit: ConfigAuditService,
  ) {}

  /**
   * Resolve a config value with full hierarchy:
   * user-level → tenant-level → global DB → env var
   */
  async get(key: string, tenantId?: string, userId?: string): Promise<string | undefined> {
    // 1. User-level override
    if (userId) {
      const userEntry = await this.findEntry(key, ConfigScope.USER, tenantId, userId);
      if (userEntry) return this.resolveValue(userEntry);
    }

    // 2. Tenant-level override
    if (tenantId) {
      const tenantEntry = await this.findEntry(key, ConfigScope.TENANT, tenantId);
      if (tenantEntry) return this.resolveValue(tenantEntry);
    }

    // 3. Global DB entry
    const globalEntry = await this.findEntry(key, ConfigScope.GLOBAL);
    if (globalEntry) return this.resolveValue(globalEntry);

    // 4. Environment variable fallback
    return this.configService.get<string>(key);
  }

  async set(dto: SetConfigDto, actorId?: string): Promise<void> {
    const scope = dto.scope ?? ConfigScope.GLOBAL;
    const existing = await this.findEntry(dto.key, scope, dto.tenantId, dto.userId);

    let storedValue = dto.value;

    // If encrypted, push to AWS Secrets Manager
    if (dto.encrypted) {
      const secretId = this.buildSecretId(dto.key, scope, dto.tenantId, dto.userId);
      await this.secrets.setSecret(secretId, dto.value);
      storedValue = secretId; // store the reference, not the value
    }

    const data = {
      key: dto.key,
      value: storedValue,
      scope,
      tenantId: dto.tenantId ?? null,
      userId: dto.userId ?? null,
      encrypted: dto.encrypted ?? false,
    };

    if (existing) {
      await (this.prisma as any).configEntry.update({ where: { id: existing.id }, data });
    } else {
      await (this.prisma as any).configEntry.create({ data });
    }

    await this.audit.log({
      key: dto.key,
      oldValue: existing ? (existing.encrypted ? '[secret]' : existing.value) : undefined,
      newValue: dto.encrypted ? '[secret]' : dto.value,
      scope,
      tenantId: dto.tenantId,
      actorId,
      action: 'SET',
    });
  }

  async delete(
    key: string,
    scope: ConfigScope,
    tenantId?: string,
    userId?: string,
    actorId?: string,
  ): Promise<void> {
    const entry = await this.findEntry(key, scope, tenantId, userId);
    if (!entry) return;

    await (this.prisma as any).configEntry.delete({ where: { id: entry.id } });

    if (entry.encrypted) {
      this.secrets.invalidateCache(entry.value);
    }

    await this.audit.log({
      key,
      oldValue: entry.encrypted ? '[secret]' : entry.value,
      scope,
      tenantId,
      actorId,
      action: 'DELETE',
    });
  }

  async listForTenant(
    tenantId: string,
  ): Promise<Array<{ key: string; value: string; scope: ConfigScope; encrypted: boolean }>> {
    const entries = await (this.prisma as any).configEntry.findMany({
      where: {
        OR: [
          { scope: ConfigScope.GLOBAL, tenantId: null },
          { scope: ConfigScope.TENANT, tenantId },
        ],
      },
      orderBy: [{ scope: 'asc' }, { key: 'asc' }],
    });

    return entries.map((e: any) => ({
      key: e.key,
      value: e.encrypted ? '[secret]' : e.value,
      scope: e.scope,
      encrypted: e.encrypted,
    }));
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private async findEntry(key: string, scope: ConfigScope, tenantId?: string, userId?: string) {
    return (this.prisma as any).configEntry.findFirst({
      where: {
        key,
        scope,
        tenantId: tenantId ?? null,
        userId: userId ?? null,
      },
    });
  }

  private async resolveValue(entry: { value: string; encrypted: boolean }): Promise<string> {
    if (!entry.encrypted) return entry.value;
    const secret = await this.secrets.getSecret(entry.value);
    return secret ?? entry.value;
  }

  private buildSecretId(
    key: string,
    scope: ConfigScope,
    tenantId?: string,
    userId?: string,
  ): string {
    const parts = ['app-config', scope.toLowerCase(), key];
    if (tenantId) parts.push(tenantId);
    if (userId) parts.push(userId);
    return parts.join('/');
  }
}
