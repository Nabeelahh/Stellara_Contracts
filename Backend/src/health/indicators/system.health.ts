import { Injectable, Logger } from '@nestjs/common';
import * as os from 'os';
import { HealthIndicatorResult, SystemHealthDetails } from '../health.types';

@Injectable()
export class SystemHealthIndicator {
  private readonly logger = new Logger(SystemHealthIndicator.name);

  async isHealthy(): Promise<HealthIndicatorResult> {
    try {
      const details = this.getSystemMetrics();
      
      let status: 'up' | 'degraded' = 'up';
      let message = 'System is healthy';
      
      // Check for potential issues
      if (details.cpu.usage > 90) {
        status = 'degraded';
        message = `CPU usage is high: ${details.cpu.usage.toFixed(2)}%`;
      }
      
      if (details.memory.percentage > 90) {
        status = 'degraded';
        message = `Memory usage is high: ${details.memory.percentage.toFixed(2)}%`;
      }

      return {
        name: 'system',
        status,
        message,
        details,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error('System health check failed', error);
      
      return {
        name: 'system',
        status: 'down',
        message: `System check failed: ${error.message}`,
        timestamp: new Date().toISOString(),
      };
    }
  }

  private getSystemMetrics(): SystemHealthDetails {
    // CPU information
    const cpus = os.cpus();
    const cpuUsage = this.getCpuUsage();
    
    // Memory information
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;
    
    // Process information
    const processMemory = process.memoryUsage();
    
    return {
      cpu: {
        usage: cpuUsage,
        count: cpus.length,
      },
      memory: {
        used: usedMemory,
        total: totalMemory,
        percentage: (usedMemory / totalMemory) * 100,
      },
      disk: {
        used: 0, // Would require additional libraries like 'diskusage'
        total: 0,
        percentage: 0,
      },
      process: {
        uptime: process.uptime(),
        memory: processMemory,
      },
    };
  }

  private getCpuUsage(): number {
    try {
      const cpus = os.cpus();
      let totalIdle = 0;
      let totalTick = 0;
      
      for (const cpu of cpus) {
        for (const type in cpu.times) {
          totalTick += cpu.times[type];
        }
        totalIdle += cpu.times.idle;
      }
      
      return 100 - Math.round((100 * totalIdle) / totalTick);
    } catch (error) {
      this.logger.warn('Could not get CPU usage', error);
      return 0;
    }
  }
}