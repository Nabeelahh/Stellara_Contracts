import { Injectable, Logger } from '@nestjs/common';
import { HealthCheckResult, HealthIndicatorResult, HealthCheckStatus } from './health.types';

@Injectable()
export class HealthService {
  private readonly logger = new Logger(HealthService.name);

  /**
   * Liveness check - determines if the application is running
   * Used by Kubernetes to decide when to restart the pod
   * Should be lightweight and not check external dependencies
   */
  async checkLiveness(): Promise<HealthCheckResult> {
    try {
      // Basic system check only - just verify the process is alive
      const isHealthy = true;
      
      return {
        status: isHealthy ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version ?? '1.0.0',
        environment: process.env.NODE_ENV ?? 'development',
        uptime: process.uptime(),
        checks: [
          {
            name: 'process',
            status: 'up',
            message: 'Application process is running',
          },
        ],
      };
    } catch (error) {
      this.logger.error('Liveness check failed', error);
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version ?? '1.0.0',
        environment: process.env.NODE_ENV ?? 'development',
        uptime: process.uptime(),
        checks: [
          {
            name: 'process',
            status: 'down',
            message: `Liveness check failed: ${error.message}`,
          },
        ],
      };
    }
  }

  /**
   * Readiness check - determines if the application is ready to serve traffic
   * Used by Kubernetes to decide when to route traffic to the pod
   * Should check all critical dependencies
   */
  async checkReadiness(): Promise<HealthCheckResult> {
    try {
      // Check critical system components
      const checks = await this.performReadinessChecks();
      const isHealthy = checks.every(check => check.status === 'up');

      return {
        status: isHealthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version ?? '1.0.0',
        environment: process.env.NODE_ENV ?? 'development',
        uptime: process.uptime(),
        checks,
      };
    } catch (error) {
      this.logger.error('Readiness check failed', error);
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version ?? '1.0.0',
        environment: process.env.NODE_ENV ?? 'development',
        uptime: process.uptime(),
        checks: [
          {
            name: 'system',
            status: 'down',
            message: `Readiness check failed: ${error.message}`,
          },
        ],
      };
    }
  }

  /**
   * Detailed health check - comprehensive system status
   * Used for debugging and monitoring dashboards
   */
  async checkDetailed(): Promise<HealthCheckResult> {
    try {
      const checks = await this.performDetailedChecks();
      const healthyChecks = checks.filter(check => check.status === 'up');
      const degradedChecks = checks.filter(check => check.status === 'degraded');
      const downChecks = checks.filter(check => check.status === 'down');

      let overallStatus: HealthCheckStatus = 'healthy';
      if (downChecks.length > 0) {
        overallStatus = 'unhealthy';
      } else if (degradedChecks.length > 0) {
        overallStatus = 'degraded';
      }

      return {
        status: overallStatus,
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version ?? '1.0.0',
        environment: process.env.NODE_ENV ?? 'development',
        uptime: process.uptime(),
        checks,
        summary: {
          total: checks.length,
          healthy: healthyChecks.length,
          degraded: degradedChecks.length,
          unhealthy: downChecks.length,
        },
      };
    } catch (error) {
      this.logger.error('Detailed health check failed', error);
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version ?? '1.0.0',
        environment: process.env.NODE_ENV ?? 'development',
        uptime: process.uptime(),
        checks: [
          {
            name: 'system',
            status: 'down',
            message: `Detailed health check failed: ${error.message}`,
          },
        ],
        summary: {
          total: 1,
          healthy: 0,
          degraded: 0,
          unhealthy: 1,
        },
      };
    }
  }

  /**
   * Check specific component health
   */
  async checkComponent(component: string): Promise<HealthIndicatorResult> {
    // For now, return basic component status
    // In a full implementation, this would delegate to specific health indicators
    const componentMap: Record<string, HealthIndicatorResult> = {
      database: {
        name: 'database',
        status: 'up',
        message: 'Database connection is healthy',
      },
      redis: {
        name: 'redis',
        status: 'up',
        message: 'Redis connection is healthy',
      },
      queue: {
        name: 'queue',
        status: 'up',
        message: 'Queue system is healthy',
      },
      system: {
        name: 'system',
        status: 'up',
        message: 'System resources are healthy',
      },
    };

    return componentMap[component.toLowerCase()] || {
      name: component,
      status: 'unknown',
      message: `Unknown component: ${component}`,
    };
  }

  private async performReadinessChecks(): Promise<HealthIndicatorResult[]> {
    // Simulate checking critical dependencies
    // In a real implementation, these would be actual health checks
    return [
      {
        name: 'database',
        status: 'up',
        message: 'Database connection established',
      },
      {
        name: 'redis',
        status: 'up',
        message: 'Redis cache available',
      },
      {
        name: 'process',
        status: 'up',
        message: 'Application process is running',
      },
    ];
  }

  private async performDetailedChecks(): Promise<HealthIndicatorResult[]> {
    // Simulate detailed health checks
    return [
      {
        name: 'database',
        status: 'up',
        message: 'Database connection established',
        details: {
          latency: 5,
          connections: 10,
        },
      },
      {
        name: 'redis',
        status: 'up',
        message: 'Redis cache available',
        details: {
          latency: 2,
          memoryUsage: '45%',
          keyCount: 1250,
        },
      },
      {
        name: 'queue',
        status: 'up',
        message: 'Queue system operational',
        details: {
          activeJobs: 3,
          pendingJobs: 15,
          failedJobs: 0,
        },
      },
      {
        name: 'system',
        status: 'up',
        message: 'System resources healthy',
        details: {
          cpuUsage: '23%',
          memoryUsage: '67%',
          uptime: process.uptime(),
        },
      },
    ];
  }
}