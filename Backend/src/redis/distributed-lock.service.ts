import { ConflictException, Injectable, RequestTimeoutException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AsyncContextService } from '../logging/services/async-context.service';
import { StructuredLoggerService } from '../logging/services/structured-logger.service';
import { RedisService } from './redis.service';
import { DistributedLockRegistry } from './distributed-lock.registry';

const LOCK_EXECUTION_ID = 'distributed-lock:execution-id';
const HELD_LOCKS = 'distributed-lock:held-locks';
const LOCK_RELEASE_SCRIPT = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
`;
const LOCK_REFRESH_SCRIPT = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0
`;

interface HeldLockRecord {
  key: string;
  redisKey: string;
  token: string;
  acquiredAt: number;
  holdCount: number;
  ttlMs: number;
  renewTimer?: NodeJS.Timeout;
}

interface LockExecutionContext {
  executionId: string;
  heldLocks: Map<string, HeldLockRecord>;
}

interface ExecuteWithLockOptions<T> {
  keys: string[];
  operationName: string;
  operation: () => T | Promise<T>;
  timeoutMs?: number;
  ttlMs?: number;
  retryIntervalMs?: number;
  deadlockWarningMs?: number;
}

@Injectable()
export class DistributedLockService {
  private readonly instanceId = randomUUID();
  private readonly defaultTimeoutMs = 30_000;
  private readonly defaultTtlMs = 30_000;
  private readonly defaultRetryIntervalMs = 100;
  private readonly defaultDeadlockWarningMs = 15_000;
  private readonly metricsKey = 'distributed-lock:metrics:global';
  private readonly metricsTtlSeconds = 7 * 24 * 60 * 60;

  constructor(
    private readonly redisService: RedisService,
    private readonly asyncContext: AsyncContextService,
    private readonly logger: StructuredLoggerService,
  ) {
    this.logger.setContext(DistributedLockService.name);
    DistributedLockRegistry.setInstance(this);
  }

  async executeWithLock<T>(options: ExecuteWithLockOptions<T>): Promise<T> {
    return this.runInExecutionContext(async () => {
      const context = this.getExecutionContext();
      const normalizedKeys = Array.from(
        new Set(options.keys.map((key) => key.trim()).filter(Boolean)),
      ).sort((left, right) => left.localeCompare(right));

      if (!normalizedKeys.length) {
        throw new Error(`No lock keys provided for ${options.operationName}.`);
      }

      this.validateLockOrdering(normalizedKeys, context, options.operationName);

      const acquiredLocks: HeldLockRecord[] = [];

      try {
        for (const key of normalizedKeys) {
          const lock = await this.acquireSingleLock(key, options.operationName, {
            timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
            ttlMs: options.ttlMs ?? this.defaultTtlMs,
            retryIntervalMs: options.retryIntervalMs ?? this.defaultRetryIntervalMs,
            deadlockWarningMs: options.deadlockWarningMs ?? this.defaultDeadlockWarningMs,
          });
          acquiredLocks.push(lock);
        }

        return await options.operation();
      } finally {
        for (const lock of acquiredLocks.reverse()) {
          await this.releaseSingleLock(lock, options.operationName);
        }
      }
    });
  }

  async getMetrics(lockKey?: string): Promise<Record<string, string>> {
    const redis = this.redisService.getClient();
    return redis.hgetall(lockKey ? this.getLockMetricsKey(lockKey) : this.metricsKey);
  }

  private async acquireSingleLock(
    key: string,
    operationName: string,
    options: Required<
      Pick<
        ExecuteWithLockOptions<unknown>,
        'timeoutMs' | 'ttlMs' | 'retryIntervalMs' | 'deadlockWarningMs'
      >
    >,
  ): Promise<HeldLockRecord> {
    const redis = this.redisService.getClient();
    const context = this.getExecutionContext();
    const existingLock = context.heldLocks.get(key);

    if (existingLock) {
      existingLock.holdCount += 1;
      existingLock.ttlMs = options.ttlMs;
      await this.refreshLock(existingLock);
      await this.recordMetric(key, 'reentrantAcquisitions');
      return existingLock;
    }

    const start = Date.now();
    const redisKey = this.getRedisLockKey(key);
    const token = `${this.instanceId}:${context.executionId}:${randomUUID()}`;
    let contentionRecorded = false;
    let deadlockWarningRecorded = false;

    while (Date.now() - start < options.timeoutMs) {
      const result = await redis.set(redisKey, token, 'PX', options.ttlMs, 'NX');

      if (result === 'OK') {
        const waitMs = Date.now() - start;
        const lock: HeldLockRecord = {
          key,
          redisKey,
          token,
          acquiredAt: Date.now(),
          holdCount: 1,
          ttlMs: options.ttlMs,
        };

        lock.renewTimer = this.startRenewTimer(lock);
        context.heldLocks.set(key, lock);

        await this.recordMetric(key, 'acquired');
        await this.recordMetric(key, 'totalWaitMs', waitMs);

        if (waitMs > 0) {
          this.logger.warn({
            msg: 'Distributed lock contention resolved',
            lockKey: key,
            operationName,
            waitMs,
          });
        }

        return lock;
      }

      if (!contentionRecorded) {
        contentionRecorded = true;
        const ttlRemainingMs = await redis.pttl(redisKey);
        await this.recordMetric(key, 'contentions');

        this.logger.warn({
          msg: 'Distributed lock contention detected',
          lockKey: key,
          operationName,
          ttlRemainingMs,
        });
      }

      const waitedMs = Date.now() - start;
      if (!deadlockWarningRecorded && waitedMs >= options.deadlockWarningMs) {
        deadlockWarningRecorded = true;
        await this.recordMetric(key, 'deadlockWarnings');

        this.logger.warn({
          msg: 'Distributed lock wait exceeded deadlock warning threshold',
          lockKey: key,
          operationName,
          waitedMs,
        });
      }

      await this.delay(options.retryIntervalMs);
    }

    await this.recordMetric(key, 'timeouts');
    await this.recordMetric(key, 'deadlockPreventions');

    throw new RequestTimeoutException(
      `Failed to acquire distributed lock for ${key} within ${options.timeoutMs}ms.`,
    );
  }

  private async releaseSingleLock(lock: HeldLockRecord, operationName: string): Promise<void> {
    if (lock.holdCount > 1) {
      lock.holdCount -= 1;
      return;
    }

    if (lock.renewTimer) {
      clearInterval(lock.renewTimer);
      lock.renewTimer = undefined;
    }

    const redis = this.redisService.getClient();
    const released = await redis.eval(LOCK_RELEASE_SCRIPT, 1, lock.redisKey, lock.token);

    this.getExecutionContext().heldLocks.delete(lock.key);

    if (Number(released) !== 1) {
      await this.recordMetric(lock.key, 'staleReleases');
      this.logger.warn({
        msg: 'Distributed lock release skipped because ownership changed',
        lockKey: lock.key,
        operationName,
      });
      return;
    }

    await this.recordMetric(lock.key, 'released');
    await this.recordMetric(lock.key, 'totalHoldMs', Date.now() - lock.acquiredAt);
  }

  private validateLockOrdering(
    requestedKeys: string[],
    context: LockExecutionContext,
    operationName: string,
  ): void {
    const heldKeys = Array.from(context.heldLocks.keys());

    for (const requestedKey of requestedKeys) {
      if (heldKeys.includes(requestedKey)) {
        continue;
      }

      const violatingKey = heldKeys.find((heldKey) => heldKey.localeCompare(requestedKey) > 0);

      if (violatingKey) {
        void this.recordMetric(requestedKey, 'deadlockPreventions');
        throw new ConflictException(
          `Deadlock prevention triggered while acquiring ${requestedKey} in ${operationName}. Acquire locks in ascending key order.`,
        );
      }
    }
  }

  private startRenewTimer(lock: HeldLockRecord): NodeJS.Timeout {
    const intervalMs = Math.max(1_000, Math.floor(lock.ttlMs / 3));
    const timer = setInterval(() => {
      void this.refreshLock(lock);
    }, intervalMs);

    timer.unref?.();
    return timer;
  }

  private async refreshLock(lock: HeldLockRecord): Promise<void> {
    const refreshed = await this.redisService
      .getClient()
      .eval(LOCK_REFRESH_SCRIPT, 1, lock.redisKey, lock.token, `${lock.ttlMs}`);

    if (Number(refreshed) !== 1) {
      this.logger.warn({
        msg: 'Distributed lock heartbeat failed because ownership changed',
        lockKey: lock.key,
      });
    }
  }

  private async runInExecutionContext<T>(callback: () => Promise<T>): Promise<T> {
    if (this.asyncContext.isActive()) {
      this.ensureExecutionContext();
      return callback();
    }

    return this.asyncContext.run(() => {
      this.ensureExecutionContext();
      return callback();
    });
  }

  private ensureExecutionContext(): void {
    if (!this.asyncContext.get<string>(LOCK_EXECUTION_ID)) {
      this.asyncContext.set(LOCK_EXECUTION_ID, randomUUID());
    }

    if (!this.asyncContext.get<Map<string, HeldLockRecord>>(HELD_LOCKS)) {
      this.asyncContext.set(HELD_LOCKS, new Map<string, HeldLockRecord>());
    }
  }

  private getExecutionContext(): LockExecutionContext {
    this.ensureExecutionContext();

    return {
      executionId: this.asyncContext.get<string>(LOCK_EXECUTION_ID)!,
      heldLocks: this.asyncContext.get<Map<string, HeldLockRecord>>(HELD_LOCKS)!,
    };
  }

  private getRedisLockKey(key: string): string {
    return `distributed-lock:${key}`;
  }

  private getLockMetricsKey(key: string): string {
    return `distributed-lock:metrics:${key}`;
  }

  private async recordMetric(lockKey: string, field: string, value = 1): Promise<void> {
    const redis = this.redisService.getClient();
    await Promise.all([
      redis.hincrbyfloat(this.metricsKey, field, value),
      redis.hincrbyfloat(this.getLockMetricsKey(lockKey), field, value),
      redis.expire(this.metricsKey, this.metricsTtlSeconds),
      redis.expire(this.getLockMetricsKey(lockKey), this.metricsTtlSeconds),
    ]);
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
