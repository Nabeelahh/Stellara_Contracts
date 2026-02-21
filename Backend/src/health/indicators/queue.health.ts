import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { HealthIndicatorResult, QueueHealthDetails } from '../health.types';

@Injectable()
export class QueueHealthIndicator {
  private readonly logger = new Logger(QueueHealthIndicator.name);

  constructor(
    @InjectQueue('default') private readonly defaultQueue: Queue,
    @InjectQueue('voice') private readonly voiceQueue: Queue,
    @InjectQueue('workflow') private readonly workflowQueue: Queue,
  ) {}

  async isHealthy(): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      // Test queue connection by getting queue counts
      const queueNames = ['default', 'voice', 'workflow'];
      const queueChecks = await Promise.all(
        queueNames.map(name => this.checkQueue(name))
      );
      
      const latency = Date.now() - startTime;
      
      const details: QueueHealthDetails = {
        connection: true,
        latency,
        queues: queueChecks,
      };

      const downQueues = queueChecks.filter(q => q.status === 'down');
      const degradedQueues = queueChecks.filter(q => q.status === 'degraded');
      
      let status = 'up';
      let message = 'All queues are healthy';
      
      if (downQueues.length > 0) {
        status = 'down';
        message = `${downQueues.length} queue(s) are down: ${downQueues.map(q => q.name).join(', ')}`;
      } else if (degradedQueues.length > 0) {
        status = 'degraded';
        message = `${degradedQueues.length} queue(s) are degraded: ${degradedQueues.map(q => q.name).join(', ')}`;
      }

      return {
        name: 'queue',
        status,
        message,
        details,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error('Queue health check failed', error);
      
      return {
        name: 'queue',
        status: 'down',
        message: `Queue system check failed: ${error.message}`,
        timestamp: new Date().toISOString(),
      };
    }
  }

  private async checkQueue(queueName: string): Promise<{
    name: string;
    active: number;
    waiting: number;
    failed: number;
    status: 'up' | 'down' | 'degraded' | 'unknown';
  }> {
    try {
      let queue: Queue;
      
      switch (queueName) {
        case 'default':
          queue = this.defaultQueue;
          break;
        case 'voice':
          queue = this.voiceQueue;
          break;
        case 'workflow':
          queue = this.workflowQueue;
          break;
        default:
          return {
            name: queueName,
            active: 0,
            waiting: 0,
            failed: 0,
            status: 'unknown',
          };
      }

      // Get queue job counts
      const counts = await queue.getJobCounts();
      
      const result = {
        name: queueName,
        active: counts.active || 0,
        waiting: counts.waiting || 0,
        failed: counts.failed || 0,
        status: 'up' as const,
      };

      // Check for potential issues
      if (result.failed > 100) {
        result.status = 'degraded';
      }
      
      if (result.waiting > 1000) {
        result.status = 'degraded';
      }

      return result;
    } catch (error) {
      this.logger.warn(`Queue ${queueName} health check failed`, error);
      
      return {
        name: queueName,
        active: 0,
        waiting: 0,
        failed: 0,
        status: 'down',
      };
    }
  }
}