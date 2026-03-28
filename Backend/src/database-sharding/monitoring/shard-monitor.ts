import { Injectable, Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';

/**
 * Shard Health Status
 */
export enum ShardHealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
  OFFLINE = 'offline',
}

/**
 * Shard Metrics
 */
export interface ShardMetrics {
  shardId: string;
  timestamp: Date;
  
  // Connection metrics
  activeConnections: number;
  idleConnections: number;
  waitingConnections: number;
  
  // Performance metrics
  queryLatency: {
    p50: number; // 50th percentile in ms
    p95: number; // 95th percentile in ms
    p99: number; // 99th percentile in ms
  };
  
  queryThroughput: number; // Queries per second
  errorRate: number; // Errors per minute
  
  // Storage metrics
  databaseSize: number; // Size in bytes
  tableSizes: Map<string, number>;
  
  // Replication lag (if applicable)
  replicationLag?: number; // Lag in milliseconds
}

/**
 * Shard Health Check Result
 */
export interface ShardHealth {
  shardId: string;
  status: ShardHealthStatus;
  lastChecked: Date;
  responseTime: number;
  message?: string;
  metrics: ShardMetrics;
}

/**
 * Alert Configuration
 */
export interface AlertConfig {
  highLatencyThreshold: number; // ms
  errorRateThreshold: number; // percentage
  sizeThreshold: number; // bytes (100GB default)
  connectionThreshold: number; // max connections
  checkInterval: number; // ms
}

/**
 * Shard Monitor Service
 * 
 * Monitors the health and performance of database shards
 * and emits alerts when thresholds are exceeded.
 */
@Injectable()
export class ShardMonitor {
  private readonly logger = new Logger(ShardMonitor.name);
  private healthChecks: Map<string, ShardHealth> = new Map();
  private metrics: Map<string, ShardMetrics[]> = new Map();
  private checkInterval?: ReturnType<typeof setInterval>;
  
  private readonly defaultConfig: AlertConfig = {
    highLatencyThreshold: 100, // 100ms
    errorRateThreshold: 5, // 5%
    sizeThreshold: 100 * 1024 * 1024 * 1024, // 100GB
    connectionThreshold: 100,
    checkInterval: 30000, // 30 seconds
  };

  constructor(private readonly eventEmitter: EventEmitter2) {}

  /**
   * Start monitoring shards
   */
  startMonitoring(
    shardIds: string[],
    config: Partial<AlertConfig> = {}
  ): void {
    const alertConfig = { ...this.defaultConfig, ...config };
    
    this.checkInterval = setInterval(async () => {
      for (const shardId of shardIds) {
        await this.checkShardHealth(shardId, alertConfig);
      }
    }, alertConfig.checkInterval);

    this.logger.log(`Started monitoring ${shardIds.length} shards`);
  }

  /**
   * Stop monitoring
   */
  stopMonitoring(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = undefined;
    }
    this.logger.log('Stopped shard monitoring');
  }

  /**
   * Check health of a specific shard
   */
  async checkShardHealth(
    shardId: string,
    config: AlertConfig
  ): Promise<ShardHealth> {
    const startTime = Date.now();
    
    try {
      // Perform health check (this would connect to actual database)
      const metrics = await this.collectMetrics(shardId);
      const responseTime = Date.now() - startTime;
      
      // Determine health status
      let status = ShardHealthStatus.HEALTHY;
      let message: string | undefined;

      if (metrics.databaseSize > config.sizeThreshold) {
        status = ShardHealthStatus.DEGRADED;
        message = `Shard size (${this.formatBytes(metrics.databaseSize)}) exceeds threshold`;
        this.emitAlert('shard.size.threshold', { shardId, metrics, config });
      }

      if (metrics.queryLatency.p99 > config.highLatencyThreshold) {
        status = ShardHealthStatus.DEGRADED;
        message = `High query latency: ${metrics.queryLatency.p99}ms`;
        this.emitAlert('shard.latency.high', { shardId, metrics, config });
      }

      if (metrics.errorRate > config.errorRateThreshold) {
        status = ShardHealthStatus.UNHEALTHY;
        message = `High error rate: ${metrics.errorRate}%`;
        this.emitAlert('shard.error.rate', { shardId, metrics, config });
      }

      if (metrics.activeConnections > config.connectionThreshold) {
        status = ShardHealthStatus.DEGRADED;
        message = `Too many connections: ${metrics.activeConnections}`;
        this.emitAlert('shard.connections.high', { shardId, metrics, config });
      }

      const health: ShardHealth = {
        shardId,
        status,
        lastChecked: new Date(),
        responseTime,
        message,
        metrics,
      };

      this.healthChecks.set(shardId, health);
      this.storeMetrics(shardId, metrics);

      return health;
    } catch (error) {
      const health: ShardHealth = {
        shardId,
        status: ShardHealthStatus.OFFLINE,
        lastChecked: new Date(),
        responseTime: Date.now() - startTime,
        message: error.message,
        metrics: this.createEmptyMetrics(shardId),
      };

      this.healthChecks.set(shardId, health);
      this.emitAlert('shard.offline', { shardId, error });

      return health;
    }
  }

  /**
   * Get health status for all shards
   */
  getAllHealth(): ShardHealth[] {
    return Array.from(this.healthChecks.values());
  }

  /**
   * Get health status for a specific shard
   */
  getShardHealth(shardId: string): ShardHealth | undefined {
    return this.healthChecks.get(shardId);
  }

  /**
   * Get metrics history for a shard
   */
  getMetricsHistory(shardId: string, limit: number = 100): ShardMetrics[] {
    const metrics = this.metrics.get(shardId) || [];
    return metrics.slice(-limit);
  }

  /**
   * Check if any shard needs splitting (>100GB)
   */
  getShardsNeedingSplitting(thresholdBytes: number = 100 * 1024 * 1024 * 1024): string[] {
    const shards: string[] = [];
    
    for (const [shardId, health] of this.healthChecks) {
      if (health.metrics.databaseSize > thresholdBytes) {
        shards.push(shardId);
      }
    }

    return shards;
  }

  /**
   * Collect metrics from a shard
   * (This would connect to actual database in production)
   */
  private async collectMetrics(shardId: string): Promise<ShardMetrics> {
    // Placeholder implementation
    // In production, this would query the database for actual metrics
    return {
      shardId,
      timestamp: new Date(),
      activeConnections: Math.floor(Math.random() * 50),
      idleConnections: Math.floor(Math.random() * 20),
      waitingConnections: Math.floor(Math.random() * 5),
      queryLatency: {
        p50: Math.random() * 50,
        p95: Math.random() * 100,
        p99: Math.random() * 200,
      },
      queryThroughput: Math.random() * 1000,
      errorRate: Math.random() * 2,
      databaseSize: Math.random() * 80 * 1024 * 1024 * 1024, // Up to 80GB
      tableSizes: new Map(),
      replicationLag: Math.random() * 100,
    };
  }

  /**
   * Store metrics for historical analysis
   */
  private storeMetrics(shardId: string, metrics: ShardMetrics): void {
    const history = this.metrics.get(shardId) || [];
    history.push(metrics);
    
    // Keep only last 1000 metrics per shard
    if (history.length > 1000) {
      history.shift();
    }
    
    this.metrics.set(shardId, history);
  }

  /**
   * Create empty metrics for offline shards
   */
  private createEmptyMetrics(shardId: string): ShardMetrics {
    return {
      shardId,
      timestamp: new Date(),
      activeConnections: 0,
      idleConnections: 0,
      waitingConnections: 0,
      queryLatency: { p50: 0, p95: 0, p99: 0 },
      queryThroughput: 0,
      errorRate: 0,
      databaseSize: 0,
      tableSizes: new Map(),
    };
  }

  /**
   * Emit an alert event
   */
  private emitAlert(event: string, payload: unknown): void {
    this.eventEmitter.emit(`shard.${event}`, payload);
    this.logger.warn(`Shard alert: ${event}`, payload);
  }

  /**
   * Format bytes to human readable string
   */
  private formatBytes(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }
}

/**
 * Shard Monitor Dashboard DTO
 */
export interface ShardDashboard {
  totalShards: number;
  healthyShards: number;
  degradedShards: number;
  unhealthyShards: number;
  offlineShards: number;
  totalSize: number;
  averageLatency: number;
  totalThroughput: number;
  shards: ShardHealth[];
  alerts: string[];
}

/**
 * Dashboard Service
 */
@Injectable()
export class ShardDashboardService {
  constructor(private readonly monitor: ShardMonitor) {}

  /**
   * Get dashboard data
   */
  getDashboard(): ShardDashboard {
    const healthStatuses = this.monitor.getAllHealth();
    
    const healthy = healthStatuses.filter(h => h.status === ShardHealthStatus.HEALTHY);
    const degraded = healthStatuses.filter(h => h.status === ShardHealthStatus.DEGRADED);
    const unhealthy = healthStatuses.filter(h => h.status === ShardHealthStatus.UNHEALTHY);
    const offline = healthStatuses.filter(h => h.status === ShardHealthStatus.OFFLINE);

    const totalSize = healthStatuses.reduce((sum, h) => sum + h.metrics.databaseSize, 0);
    const averageLatency = healthStatuses.length > 0
      ? healthStatuses.reduce((sum, h) => sum + h.metrics.queryLatency.p95, 0) / healthStatuses.length
      : 0;
    const totalThroughput = healthStatuses.reduce((sum, h) => sum + h.metrics.queryThroughput, 0);

    const alerts: string[] = [];
    for (const health of healthStatuses) {
      if (health.message) {
        alerts.push(`${health.shardId}: ${health.message}`);
      }
    }

    return {
      totalShards: healthStatuses.length,
      healthyShards: healthy.length,
      degradedShards: degraded.length,
      unhealthyShards: unhealthy.length,
      offlineShards: offline.length,
      totalSize,
      averageLatency,
      totalThroughput,
      shards: healthStatuses,
      alerts,
    };
  }
}
