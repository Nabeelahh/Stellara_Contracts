import { Injectable, Logger } from '@nestjs/common';
import { QueueService } from '../services/queue.service';

/**
 * Example service showing how to use the QueueService
 * This demonstrates best practices for job queue integration
 */
@Injectable()
export class QueueExampleService {
  private readonly logger = new Logger(QueueExampleService.name);

  constructor(private readonly queueService: QueueService) {}

  /**
   * Example: Queue a contract deployment job
   */
  async queueContractDeployment(
    contractName: string,
    contractCode: string,
    network: string,
    initializer?: string,
  ) {
    try {
      const job = await this.queueService.addJob(
        'deploy-contract',
        'deploy',
        {
          contractName,
          contractCode,
          network,
          initializer,
        },
        {
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 2000,
          },
          timeout: 60000, // 60 seconds
          removeOnComplete: false,
          removeOnFail: false,
        },
      );

      this.logger.log(`Contract deployment job queued: ${job!.id}`);
      return job;
    } catch (error) {
      this.logger.error(
        `Failed to queue contract deployment: ${error.message}`,
      );
      throw error;
    }
  }

  /**
   * Example: Queue TTS processing job
   */
  async queueTtsProcessing(
    text: string,
    voiceId: string,
    language: string = 'en',
    speed: number = 1.0,
    sessionId?: string,
  ) {
    try {
      const job = await this.queueService.addJob(
        'process-tts',
        'process',
        {
          text,
          voiceId,
          language,
          speed,
          sessionId,
        },
        {
          attempts: 2,
          backoff: {
            type: 'exponential',
            delay: 1000,
          },
          timeout: 30000, // 30 seconds
        },
      );

      this.logger.log(`TTS processing job queued: ${job!.id}`);
      return job;
    } catch (error) {
      this.logger.error(`Failed to queue TTS processing: ${error.message}`);
      throw error;
    }
  }

  /**
   * Example: Queue market news indexing job
   */
  async queueMarketNewsIndexing(
    source: string,
    startDate?: string,
    endDate?: string,
    limit?: number,
  ) {
    try {
      const job = await this.queueService.addJob(
        'index-market-news',
        'index',
        {
          source,
          startDate,
          endDate,
          limit: limit || 100,
        },
        {
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 5000,
          },
          timeout: 120000, // 2 minutes
        },
      );

      this.logger.log(`Market news indexing job queued: ${job!.id}`);
      return job;
    } catch (error) {
      this.logger.error(
        `Failed to queue market news indexing: ${error.message}`,
      );
      throw error;
    }
  }

  /**
   * Example: Monitor job status
   */
  async monitorJobStatus(queueName: string, jobId: string) {
    try {
      const jobInfo = await this.queueService.getJobInfo(queueName, jobId);

      if (!jobInfo) {
        this.logger.warn(`Job ${jobId} not found in queue ${queueName}`);
        return null;
      }

      this.logger.log(
        `Job ${jobId} status: ${jobInfo.status} (${jobInfo.progress}% complete)`,
      );
      return jobInfo;
    } catch (error) {
      this.logger.error(`Failed to monitor job: ${error.message}`);
      throw error;
    }
  }

  /**
   * Example: Handle job completion/failure
   */
  async handleJobCompletion(queueName: string, jobId: string) {
    try {
      const jobInfo = await this.queueService.getJobInfo(queueName, jobId);

      if (!jobInfo) {
        throw new Error(`Job ${jobId} not found`);
      }

      if (jobInfo.result?.success) {
        this.logger.log(
          `Job completed successfully: ${JSON.stringify(jobInfo.result.data)}`,
        );
        // Do something with the result
      } else {
        this.logger.error(`Job failed: ${jobInfo.error}`);
        // Handle failure
      }

      return jobInfo;
    } catch (error) {
      this.logger.error(`Failed to handle job completion: ${error.message}`);
      throw error;
    }
  }

  /**
   * Example: Retry failed job
   */
  async retryFailedJob(queueName: string, jobId: string) {
    try {
      const requeuedJob = await this.queueService.requeueJob(queueName, jobId);

      if (!requeuedJob) {
        throw new Error(`Failed to requeue job ${jobId}`);
      }

      this.logger.log(`Failed job requeued: ${jobId} → ${requeuedJob.id}`);
      return requeuedJob;
    } catch (error) {
      this.logger.error(`Failed to retry job: ${error.message}`);
      throw error;
    }
  }

  /**
   * Example: Get queue statistics for monitoring
   */
  async getQueueMetrics(queueName: string) {
    try {
      const stats = await this.queueService.getQueueStats(queueName);

      this.logger.log(`Queue ${queueName} metrics:`, stats);

      // Calculate health metrics
      const totalJobs = Object.values(stats).reduce(
        (a: number, b: number) => a + b,
        0,
      );
      const failureRate = totalJobs > 0 ? (stats.failed / totalJobs) * 100 : 0;

      return {
        ...stats,
        totalJobs,
        failureRate: failureRate.toFixed(2) + '%',
        health:
          failureRate < 5
            ? 'healthy'
            : failureRate < 10
              ? 'warning'
              : 'critical',
      };
    } catch (error) {
      this.logger.error(`Failed to get queue metrics: ${error.message}`);
      throw error;
    }
  }

  /**
   * Example: Clear dead-letter queue by requeuing
   */
  async processDeadLetterQueue(queueName: string, limit: number = 10) {
    try {
      const dlqItems = await this.queueService.getDeadLetterQueue(
        queueName,
        limit,
      );

      this.logger.log(`Found ${dlqItems.length} items in DLQ for ${queueName}`);

      if (dlqItems.length > 0) {
        const requeuedJobs = await this.queueService.requeueFromDLQ(
          queueName,
          limit,
        );
        this.logger.log(`Requeued ${requeuedJobs.length} jobs from DLQ`);
        return requeuedJobs;
      }

      return [];
    } catch (error) {
      this.logger.error(`Failed to process DLQ: ${error.message}`);
      throw error;
    }
  }
}
