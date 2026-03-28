import { DistributedLockRegistry } from './distributed-lock.registry';

export interface DistributedLockExecutionContext {
  args: unknown[];
  instance: object;
  methodName: string;
}

export type DistributedLockKeyResolver =
  | string
  | string[]
  | ((context: DistributedLockExecutionContext) => string | string[]);

export interface DistributedLockOptions {
  key: DistributedLockKeyResolver;
  timeoutMs?: number;
  ttlMs?: number;
  retryIntervalMs?: number;
  deadlockWarningMs?: number;
}

function isPrimitive(value: unknown): boolean {
  return (
    value === null ||
    value === undefined ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    typeof value === 'bigint'
  );
}

function getPathValue(source: unknown, path: string): unknown {
  if (!source || typeof source !== 'object') {
    return undefined;
  }

  return path
    .split('.')
    .reduce<unknown>(
      (current, segment) =>
        current && typeof current === 'object'
          ? (current as Record<string, unknown>)[segment]
          : undefined,
      source,
    );
}

function resolvePlaceholderValue(
  placeholder: string,
  context: DistributedLockExecutionContext,
): string {
  const argIndexMatch = placeholder.match(/^arg(\d+)$/);
  if (argIndexMatch) {
    const value = context.args[Number(argIndexMatch[1])];
    if (value === undefined || value === null) {
      throw new Error(
        `Unable to resolve lock placeholder {${placeholder}} for ${context.methodName}.`,
      );
    }

    return String(value);
  }

  for (const arg of context.args) {
    const value = getPathValue(arg, placeholder);
    if (value !== undefined && value !== null) {
      return String(value);
    }
  }

  const instanceValue = getPathValue(context.instance, placeholder);
  if (instanceValue !== undefined && instanceValue !== null) {
    return String(instanceValue);
  }

  if (placeholder === 'id' && context.args.length >= 1 && isPrimitive(context.args[0])) {
    return String(context.args[0]);
  }

  throw new Error(`Unable to resolve lock placeholder {${placeholder}} for ${context.methodName}.`);
}

export function resolveDistributedLockKeys(
  resolver: DistributedLockKeyResolver,
  context: DistributedLockExecutionContext,
): string[] {
  const rawKeys = typeof resolver === 'function' ? resolver(context) : resolver;
  const keys = (Array.isArray(rawKeys) ? rawKeys : [rawKeys]).map((rawKey) =>
    rawKey.replace(/\{([^}]+)\}/g, (_, placeholder) =>
      resolvePlaceholderValue(placeholder, context),
    ),
  );

  const normalizedKeys = Array.from(new Set(keys.map((key) => key.trim()).filter(Boolean)));

  if (!normalizedKeys.length) {
    throw new Error(`No distributed lock keys were resolved for ${context.methodName}.`);
  }

  return normalizedKeys;
}

export function distributedlock(options: DistributedLockOptions) {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor,
  ): PropertyDescriptor {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: unknown[]) {
      const methodName = `${target.constructor.name}.${String(propertyKey)}`;
      const keys = resolveDistributedLockKeys(options.key, {
        args,
        instance: this,
        methodName,
      });

      return DistributedLockRegistry.getInstance().executeWithLock({
        keys,
        operationName: methodName,
        timeoutMs: options.timeoutMs,
        ttlMs: options.ttlMs,
        retryIntervalMs: options.retryIntervalMs,
        deadlockWarningMs: options.deadlockWarningMs,
        operation: () => Promise.resolve(originalMethod.apply(this, args)),
      });
    };

    return descriptor;
  };
}

export const DistributedLock = distributedlock;
