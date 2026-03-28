import { Injectable, Logger } from '@nestjs/common';
import { EventListenerService } from '../events/event-listener.service';
import { StorageService } from '../storage/storage.service';

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  uptime: number;
  version: string;
  components: {
    eventListener: ComponentHealth;
    storage: ComponentHealth;
    processor: ComponentHealth;
  };
  sync: SyncStatus;
  metrics: HealthMetrics;
}

export interface ComponentHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  lastCheck: Date;
  responseTime?: number;
  error?: string;
  details?: any;
}

export interface SyncStatus {
  isSyncing: boolean;
  currentLedger: number;
  latestLedger: number;
  lag: number;
  lastSync: Date;
  syncRate: number; // ledgers per minute
}

export interface HealthMetrics {
  eventsProcessed: number;
  eventsPerMinute: number;
  queueSize: number;
  errorRate: number;
  memoryUsage: number;
  cpuUsage: number;
}

@Injectable()
export class HealthCheckService {
  private readonly logger = new Logger(HealthCheckService.name);
  private startTime = Date.now();
  private lastHealthCheck = new Date();
  private healthHistory: HealthStatus[] = [];

  constructor(
    private eventListener: EventListenerService,
    private storage: StorageService,
  ) {}

  async getHealthStatus(): Promise<HealthStatus> {
    const timestamp = new Date();
    const uptime = Date.now() - this.startTime;

    // Check individual components
    const eventListenerHealth = await this.checkEventListenerHealth();
    const storageHealth = await this.checkStorageHealth();
    const processorHealth = await this.checkProcessorHealth();

    // Get sync status
    const syncStatus = await this.getSyncStatus();

    // Get metrics
    const metrics = await this.getHealthMetrics();

    // Determine overall health
    const overallStatus = this.determineOverallStatus([
      eventListenerHealth.status,
      storageHealth.status,
      processorHealth.status,
    ]);

    const healthStatus: HealthStatus = {
      status: overallStatus,
      timestamp,
      uptime,
      version: process.env.APP_VERSION || '1.0.0',
      components: {
        eventListener: eventListenerHealth,
        storage: storageHealth,
        processor: processorHealth,
      },
      sync: syncStatus,
      metrics,
    };

    // Store health history
    this.healthHistory.push(healthStatus);
    if (this.healthHistory.length > 100) {
      this.healthHistory.shift();
    }

    this.lastHealthCheck = timestamp;
    return healthStatus;
  }

  private async checkEventListenerHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      const isRunning = this.eventListener.isRunning();
      const currentCursor = this.eventListener.getCurrentCursor();
      const reconnectStatus = this.eventListener.getReconnectStatus();

      const responseTime = Date.now() - startTime;

      let status: ComponentHealth['status'] = 'healthy';
      let error: string | undefined;

      if (!isRunning) {
        status = 'unhealthy';
        error = 'Event listener is not running';
      } else if (reconnectStatus.attempts > 0) {
        status = 'degraded';
        error = `Event listener has ${reconnectStatus.attempts} reconnect attempts`;
      }

      return {
        status,
        lastCheck: new Date(),
        responseTime,
        error,
        details: {
          isRunning,
          currentCursor,
          reconnectStatus,
        },
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        lastCheck: new Date(),
        responseTime: Date.now() - startTime,
        error: error.message,
      };
    }
  }

  private async checkStorageHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      // Test database connectivity
      const latestLedger = await this.storage.getLatestLedger();
      const eventCount = await this.storage.getProcessedEventCount();

      const responseTime = Date.now() - startTime;

      return {
        status: 'healthy',
        lastCheck: new Date(),
        responseTime,
        details: {
          latestLedger,
          totalEvents: eventCount,
        },
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        lastCheck: new Date(),
        responseTime: Date.now() - startTime,
        error: error.message,
      };
    }
  }

  private async checkProcessorHealth(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      // In a real implementation, check processor queue and stats
      const stats = await this.getProcessingStats();
      const responseTime = Date.now() - startTime;

      let status: ComponentHealth['status'] = 'healthy';
      let error: string | undefined;

      if (stats.queueSize > 1000) {
        status = 'degraded';
        error = `Large queue size: ${stats.queueSize}`;
      }

      if (stats.errorRate > 10) {
        status = 'unhealthy';
        error = `High error rate: ${stats.errorRate}%`;
      }

      return {
        status,
        lastCheck: new Date(),
        responseTime,
        error,
        details: stats,
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        lastCheck: new Date(),
        responseTime: Date.now() - startTime,
        error: error.message,
      };
    }
  }

  private async getSyncStatus(): Promise<SyncStatus> {
    try {
      const currentLedger = await this.storage.getLatestLedger();
      const latestLedger = await this.getLatestStellarLedger();

      const lag = latestLedger - (currentLedger || 0);
      const isSyncing = this.eventListener.isRunning();

      const lastSync = new Date(); // In a real implementation, track last successful sync

      // Calculate sync rate (ledgers per minute)
      const syncRate = await this.calculateSyncRate();

      return {
        isSyncing,
        currentLedger: currentLedger || 0,
        latestLedger,
        lag,
        lastSync,
        syncRate,
      };
    } catch (error) {
      this.logger.error('Error getting sync status:', error);
      return {
        isSyncing: false,
        currentLedger: 0,
        latestLedger: 0,
        lag: 0,
        lastSync: new Date(),
        syncRate: 0,
      };
    }
  }

  private async getHealthMetrics(): Promise<HealthMetrics> {
    try {
      const stats = await this.getProcessingStats();
      const memUsage = process.memoryUsage();

      // Calculate events per minute
      const eventsPerMinute = await this.calculateEventsPerMinute();

      // Calculate error rate
      const errorRate = await this.calculateErrorRate();

      return {
        eventsProcessed: stats.processedCount,
        eventsPerMinute,
        queueSize: stats.queueSize,
        errorRate,
        memoryUsage: memUsage.heapUsed / 1024 / 1024, // MB
        cpuUsage: process.cpuUsage().user / 1000000, // seconds
      };
    } catch (error) {
      this.logger.error('Error getting health metrics:', error);
      return {
        eventsProcessed: 0,
        eventsPerMinute: 0,
        queueSize: 0,
        errorRate: 0,
        memoryUsage: 0,
        cpuUsage: 0,
      };
    }
  }

  private determineOverallStatus(statuses: ComponentHealth['status'][]): HealthStatus['status'] {
    if (statuses.some((status) => status === 'unhealthy')) {
      return 'unhealthy';
    }

    if (statuses.some((status) => status === 'degraded')) {
      return 'degraded';
    }

    return 'healthy';
  }

  private async getLatestStellarLedger(): Promise<number> {
    // In a real implementation, query Stellar network for latest ledger
    // For now, return a mock value
    return 1000000;
  }

  private async calculateSyncRate(): Promise<number> {
    // Calculate how many ledgers per minute we're processing
    // This would use historical data in a real implementation
    return 60; // Mock: 60 ledgers per minute
  }

  private async calculateEventsPerMinute(): Promise<number> {
    // Calculate events processed in the last minute
    // This would query the database for recent events
    return 100; // Mock: 100 events per minute
  }

  private async calculateErrorRate(): Promise<number> {
    // Calculate error rate as percentage
    const stats = await this.getProcessingStats();

    if (stats.processedCount === 0) {
      return 0;
    }

    return (stats.failedCount / stats.processedCount) * 100;
  }

  private async getProcessingStats(): Promise<{
    queueSize: number;
    processedCount: number;
    failedCount: number;
    isProcessing: boolean;
  }> {
    // In a real implementation, get stats from the processor service
    return {
      queueSize: 0,
      processedCount: 0,
      failedCount: 0,
      isProcessing: false,
    };
  }

  async getHealthHistory(limit: number = 50): Promise<HealthStatus[]> {
    return this.healthHistory.slice(-limit);
  }

  async getDetailedHealthReport(): Promise<{
    current: HealthStatus;
    history: HealthStatus[];
    trends: {
      statusChanges: number;
      averageResponseTime: number;
      errorTrend: 'improving' | 'stable' | 'degrading';
      syncTrend: 'improving' | 'stable' | 'degrading';
    };
  }> {
    const current = await this.getHealthStatus();
    const history = await this.getHealthHistory();

    const trends = this.analyzeTrends(history);

    return {
      current,
      history,
      trends,
    };
  }

  private analyzeTrends(history: HealthStatus[]): {
    statusChanges: number;
    averageResponseTime: number;
    errorTrend: 'improving' | 'stable' | 'degrading';
    syncTrend: 'improving' | 'stable' | 'degrading';
  } {
    if (history.length < 2) {
      return {
        statusChanges: 0,
        averageResponseTime: 0,
        errorTrend: 'stable',
        syncTrend: 'stable',
      };
    }

    // Count status changes
    let statusChanges = 0;
    for (let i = 1; i < history.length; i++) {
      if (history[i].status !== history[i - 1].status) {
        statusChanges++;
      }
    }

    // Calculate average response time
    const responseTimes = history
      .map((h) => Object.values(h.components).map((c) => c.responseTime || 0))
      .flat()
      .filter((t) => t > 0);

    const averageResponseTime =
      responseTimes.length > 0
        ? responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length
        : 0;

    // Analyze error trend
    const recentErrors = history.slice(-10).map((h) => h.metrics.errorRate);
    const errorTrend = this.calculateTrend(recentErrors);

    // Analyze sync trend
    const recentSyncLag = history.slice(-10).map((h) => h.sync.lag);
    const syncTrend = this.calculateTrend(recentSyncLag, true); // Lower is better for lag

    return {
      statusChanges,
      averageResponseTime,
      errorTrend,
      syncTrend,
    };
  }

  private calculateTrend(
    values: number[],
    lowerIsBetter: boolean = false,
  ): 'improving' | 'stable' | 'degrading' {
    if (values.length < 2) return 'stable';

    const firstHalf = values.slice(0, Math.floor(values.length / 2));
    const secondHalf = values.slice(Math.floor(values.length / 2));

    const firstAvg = firstHalf.reduce((sum, val) => sum + val, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, val) => sum + val, 0) / secondHalf.length;

    const difference = secondAvg - firstAvg;
    const threshold = 0.1; // 10% change threshold

    if (Math.abs(difference) < threshold) {
      return 'stable';
    }

    if (lowerIsBetter) {
      return difference < 0 ? 'improving' : 'degrading';
    } else {
      return difference > 0 ? 'improving' : 'degrading';
    }
  }

  isHealthy(): boolean {
    return this.healthHistory.length > 0
      ? this.healthHistory[this.healthHistory.length - 1].status === 'healthy'
      : false;
  }

  getLastHealthCheck(): Date {
    return this.lastHealthCheck;
  }
}
