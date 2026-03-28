import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import * as os from 'node:os';
import { PostgresService } from '../database/postgres.service';
import { RedisService } from '../redis/redis.service';
import { parseDurationToMilliseconds } from '../common/utils/duration.util';
import { WebsocketLoadBalancerService } from '../websocket/load-balancer.service';

interface DependencySnapshot {
  database: boolean;
  redis: boolean;
}

interface DeploymentSnapshot {
  environment: string;
  slot: string;
  activeColor: string;
  trafficStatus: string;
  releaseVersion: string;
  commitSha: string;
  buildId: string;
}

@Injectable()
export class ApplicationStateService {
  private readonly logger = new Logger(ApplicationStateService.name);
  private readonly startedAt = new Date();
  private readonly drainTimeoutMs: number;

  private activeRequests = 0;
  private startupComplete = false;
  private startupError?: string;
  private draining = false;
  private shutdownSignal?: string;
  private dependencySnapshot: DependencySnapshot = {
    database: false,
    redis: false,
  };
  private readonly deploymentSnapshot: DeploymentSnapshot = {
    environment: process.env.DEPLOYMENT_ENVIRONMENT ?? process.env.NODE_ENV ?? 'development',
    slot: process.env.DEPLOYMENT_SLOT ?? 'standalone',
    activeColor: process.env.ACTIVE_COLOR ?? 'unknown',
    trafficStatus: process.env.TRAFFIC_STATUS ?? 'warming',
    releaseVersion: process.env.RELEASE_VERSION ?? 'local',
    commitSha: process.env.RELEASE_COMMIT_SHA ?? 'local',
    buildId: process.env.RELEASE_BUILD_ID ?? 'manual',
  };
  private drainWaiters: Array<() => void> = [];

  constructor(
    private readonly postgres: PostgresService,
    private readonly redisService: RedisService,
    private readonly wsLoadBalancer: WebsocketLoadBalancerService,
  ) {
    this.drainTimeoutMs = parseDurationToMilliseconds(
      process.env.SHUTDOWN_DRAIN_TIMEOUT_MS,
      60_000,
    );
  }

  getDrainTimeoutMs(): number {
    return this.drainTimeoutMs;
  }

  async verifyStartupDependencies(): Promise<void> {
    try {
      await this.postgres.healthCheck();
      this.dependencySnapshot.database = true;
    } catch (error) {
      this.startupError = `Database dependency check failed: ${error.message}`;
      this.logger.error(this.startupError);
      throw error;
    }

    try {
      await this.redisService.ping();
      this.dependencySnapshot.redis = true;
    } catch (error) {
      this.startupError = `Redis dependency check failed: ${error.message}`;
      this.logger.error(this.startupError);
      throw error;
    }
  }

  markReady(): void {
    this.startupComplete = true;
    this.startupError = undefined;
    this.deploymentSnapshot.trafficStatus = 'ready';
  }

  incrementActiveRequests(): void {
    this.activeRequests += 1;
  }

  decrementActiveRequests(): void {
    this.activeRequests = Math.max(0, this.activeRequests - 1);

    if (this.activeRequests === 0) {
      this.resolveDrainWaiters();
    }
  }

  shouldRejectIncomingRequest(path: string): boolean {
    if (!this.draining) {
      return false;
    }

    return !path.includes('/health');
  }

  async beginDrain(signal: string): Promise<void> {
    if (this.draining) {
      return;
    }

    this.draining = true;
    this.shutdownSignal = signal;
    this.deploymentSnapshot.trafficStatus = 'draining';
    this.logger.warn(
      `Received ${signal}. Entering drain mode with ${this.activeRequests} active requests and starting WebSocket drain.`,
    );

    // Update WebSocket load balancer status to draining
    await this.wsLoadBalancer.setDrainingStatus();
  }

  async waitForInflightRequests(): Promise<void> {
    if (this.activeRequests === 0) {
      return;
    }

    await Promise.race([
      new Promise<void>((resolve) => {
        this.drainWaiters.push(resolve);
      }),
      new Promise<void>((resolve) => {
        setTimeout(resolve, this.drainTimeoutMs);
      }),
    ]);
  }

  isReady(): boolean {
    return (
      this.startupComplete &&
      !this.draining &&
      this.dependencySnapshot.database &&
      this.dependencySnapshot.redis
    );
  }

  assertReady(): void {
    if (!this.isReady()) {
      throw new ServiceUnavailableException(this.getReadinessSnapshot());
    }
  }

  getAdaptiveLoadFactor(): number {
    const memoryRatio = process.memoryUsage().rss / os.totalmem();

    if (this.draining) {
      return 0.25;
    }

    if (memoryRatio >= 0.85 || this.activeRequests >= 300) {
      return 0.5;
    }

    if (memoryRatio >= 0.7 || this.activeRequests >= 150) {
      return 0.75;
    }

    return 1;
  }

  getLivenessSnapshot() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
      uptimeMs: Date.now() - this.startedAt.getTime(),
    };
  }

  getReadinessSnapshot() {
    return {
      ready: this.isReady(),
      startupComplete: this.startupComplete,
      draining: this.draining,
      activeRequests: this.activeRequests,
      drainTimeoutMs: this.drainTimeoutMs,
      dependencies: this.dependencySnapshot,
      startupError: this.startupError,
      shutdownSignal: this.shutdownSignal,
      adaptiveLoadFactor: this.getAdaptiveLoadFactor(),
    };
  }

  async getHealthSnapshot() {
    const wsHealth = await this.wsLoadBalancer.getHealthStatus();
    return {
      ...this.getLivenessSnapshot(),
      ...this.getReadinessSnapshot(),
      deployment: this.deploymentSnapshot,
      websocket: wsHealth,
    };
  }

  private resolveDrainWaiters(): void {
    const waiters = [...this.drainWaiters];
    this.drainWaiters = [];
    waiters.forEach((resolve) => resolve());
  }
}
