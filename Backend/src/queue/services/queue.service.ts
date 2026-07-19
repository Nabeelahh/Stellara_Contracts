import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import type { Queue, Job } from 'bull';
import { JobData, JobResult, JobStatus, JobInfo } from '../types/job.types';
import { RedisService } from '../../redis/redis.service';
import { QueueJobTracingWrapper } from '../../observability/middleware/queue-job-tracing.wrapper';
import { TraceContext } from '../../observability/types/trace-context.interface';

@Injectable()
export class QueueService {
  private readonly logger = new Logger(QueueService.name);

  // DLQ key prefix in Redis
  private readonly DLQ_PREFIX = 'queue:dlq:';

  constructor(
    @InjectQueue('deploy-contract') private deployContractQueue: Queue,
    @InjectQueue('process-tts') private processTtsQueue: Queue,
    @InjectQueue('index-market-news') private indexMarketNewsQueue: Queue,
    private readonly redisService: RedisService,
    private readonly queueJobTracingWrapper: QueueJobTracingWrapper,
  ) {
    this.initializeQueues();
  }

  private initializeQueues() {
    // Setup event listeners for all queues
    [
      this.deployContractQueue,
      this.processTtsQueue,
      this.indexMarketNewsQueue,
    ].forEach((queue) => {
      queue.on('failed', async (job: Job, error: Error) => {
        await this.handleJobFailure(job, error);
      });

      queue.on('completed', async (job: Job) => {
        this.logger.log(`Job ${job.id} completed: ${job.name}`);
      });

      queue.on('error', (error: Error) => {
        this.logger.error(`Queue error: ${error.message}`, error.stack);
      });
    });
  }

  private getQueueByName(queueName: string): Queue {
    switch (queueName) {
      case 'deploy-contract':
        return this.deployContractQueue;
      case 'process-tts':
        return this.processTtsQueue;
      case 'index-market-news':
        return this.indexMarketNewsQueue;
      default:
        throw new Error(`Unknown queue: ${queueName}`);
    }
  }

  /**
   * Add a job to the queue
   */
  async addJob<T extends JobData>(
    queueName: string,
    jobName: string,
    data: T,
    options: any = {},
    parentTraceContext?: TraceContext,
  ): Promise<Job<T>> {
    const queue = this.getQueueByName(queueName);

    // Inject trace context if parentTraceContext is provided
    let jobData = data;
    if (parentTraceContext) {
      jobData = this.queueJobTracingWrapper.injectTraceContext(data, parentTraceContext);
    }

    const job = await queue.add(jobName, jobData, {
      removeOnComplete: false, // Keep completed jobs for tracking
      removeOnFail: false, // Keep failed jobs for analysis
      ...options,
    });

    this.logger.log(`Job added: ${jobName} with ID: ${job.id}`);
    return job;
  }

  /**
   * Get job status and info
   */
  async getJobInfo(
    queueName: string,
    jobId: string | number,
  ): Promise<JobInfo | null> {
    const queue = this.getQueueByName(queueName);
    const job = await queue.getJob(jobId);

    if (!job) {
      return null;
    }

    const state = await job.getState();
    const progress = job.progress();

    return {
      id: job.id.toString(),
      name: job.name,
      status: this.mapJobState(state),
      progress: typeof progress === 'number' ? progress : 0,
      attempts: job.attemptsMade,
      maxAttempts: job.opts.attempts || 1,
      data: job.data,
      result: job.returnvalue
        ? { success: true, data: job.returnvalue }
        : undefined,
      error: job.failedReason || undefined,
      createdAt: new Date(job.timestamp),
      processedAt: job.processedOn ? new Date(job.processedOn) : undefined,
      completedAt: job.finishedOn ? new Date(job.finishedOn) : undefined,
    };
  }

  /**
   * Get all jobs with optional filtering by status
   */
  async getQueueJobs(
    queueName: string,
    statuses: string[] = ['active', 'completed', 'failed', 'delayed'],
  ): Promise<JobInfo[]> {
    const queue = this.getQueueByName(queueName);
    const jobs: Job[] = [];

    for (const status of statuses) {
      const statusJobs = await queue.getJobs(status as any);
      jobs.push(...statusJobs);
    }

    return Promise.all(
      jobs.map(async (job) => {
        const state = await job.getState();
        const progress = job.progress();

        return {
          id: job.id.toString(),
          name: job.name,
          status: this.mapJobState(state),
          progress: typeof progress === 'number' ? progress : 0,
          attempts: job.attemptsMade,
          maxAttempts: job.opts.attempts || 1,
          data: job.data,
          result: job.returnvalue
            ? { success: true, data: job.returnvalue }
            : undefined,
          error: job.failedReason || undefined,
          createdAt: new Date(job.timestamp),
          processedAt: job.processedOn ? new Date(job.processedOn) : undefined,
          completedAt: job.finishedOn ? new Date(job.finishedOn) : undefined,
        };
      }),
    );
  }

  /**
   * Get dead-letter queue (permanently failed jobs)
   */
  async getDeadLetterQueue(
    queueName: string,
    limit: number = 50,
  ): Promise<any[]> {
    const dlqKey = `${this.DLQ_PREFIX}${queueName}`;
    const dlqData = await this.redisService.client.lRange(dlqKey, 0, limit - 1);
    return dlqData.map((item) => {
      try {
        return JSON.parse(item);
      } catch {
        return item;
      }
    });
  }

  /**
   * Requeue a job that previously failed
   */
  async requeueJob(
    queueName: string,
    jobId: string | number,
  ): Promise<Job | null> {
    const queue = this.getQueueByName(queueName);
    const job = await queue.getJob(jobId);

    if (!job) {
      throw new Error(`Job ${jobId} not found in queue ${queueName}`);
    }

    // Create a new job with same data
    const newJob = await queue.add(job.name, job.data, {
      removeOnComplete: false,
      removeOnFail: false,
      attempts: job.opts.attempts || 3,
      backoff: job.opts.backoff,
    });

    this.logger.log(
      `Job requeued: ${job.name} (original ID: ${jobId}, new ID: ${newJob.id})`,
    );
    return newJob;
  }

  /**
   * Requeue multiple failed jobs from DLQ
   */
  async requeueFromDLQ(queueName: string, limit: number = 10): Promise<Job[]> {
    const dlqKey = `${this.DLQ_PREFIX}${queueName}`;
    const dlqData = await this.redisService.client.lRange(dlqKey, 0, limit - 1);
    const requeuedJobs: Job[] = [];

    for (const item of dlqData) {
      try {
        const jobData = JSON.parse(item);
        const queue = this.getQueueByName(queueName);
        const newJob = await queue.add(jobData.name, jobData.data, {
          removeOnComplete: false,
          removeOnFail: false,
          attempts: jobData.maxAttempts || 3,
        });
        requeuedJobs.push(newJob);
      } catch (error) {
        this.logger.error(`Failed to requeue DLQ item: ${error.message}`);
      }
    }

    // Remove requeued items from DLQ
    if (requeuedJobs.length > 0) {
      await this.redisService.client.lTrim(dlqKey, requeuedJobs.length, -1);
    }

    return requeuedJobs;
  }

  /**
   * Purge jobs from a queue
   */
  async purgeQueue(queueName: string): Promise<number> {
    const queue = this.getQueueByName(queueName);
    const jobs = await queue.clean(0, 'failed');
    const count = jobs.length;
    this.logger.log(`Purged ${count} jobs from queue ${queueName}`);
    return count;
  }

  /**
   * Get queue statistics
   */
  async getQueueStats(queueName: string): Promise<{
    active: number;
    completed: number;
    failed: number;
    delayed: number;
    waiting: number;
  }> {
    const queue = this.getQueueByName(queueName);
    const counts = await queue.getJobCounts();

    return {
      active: counts.active || 0,
      completed: counts.completed || 0,
      failed: counts.failed || 0,
      delayed: counts.delayed || 0,
      waiting: counts.waiting || 0,
    };
  }

  /**
   * Update job progress
   */
  async updateJobProgress(
    queueName: string,
    jobId: string | number,
    progress: number,
  ): Promise<void> {
    const queue = this.getQueueByName(queueName);
    const job = await queue.getJob(jobId);

    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    await job.progress(progress);
  }

  /**
   * Handle job failure - move to DLQ if max retries exceeded
   */
  private async handleJobFailure(job: Job, error: Error): Promise<void> {
    const maxAttempts = job.opts.attempts || 1;
    const attempts = job.attemptsMade;

    this.logger.error(
      `Job ${job.id} (${job.name}) failed: ${error.message} (attempt ${attempts}/${maxAttempts})`,
    );

    // If max retries exceeded, move to DLQ
    if (attempts >= maxAttempts) {
      const dlqKey = `${this.DLQ_PREFIX}${job.queue.name}`;
      const dlqItem = JSON.stringify({
        id: job.id,
        name: job.name,
        data: job.data,
        error: error.message,
        attempts: attempts,
        maxAttempts: maxAttempts,
        failedAt: new Date().toISOString(),
      });

      try {
        await this.redisService.client.rPush(dlqKey, dlqItem);
        this.logger.warn(
          `Job ${job.id} (${job.name}) moved to DLQ after ${attempts} attempts`,
        );
      } catch (dlqError) {
        this.logger.error(`Failed to move job to DLQ: ${dlqError.message}`);
      }
    }
  }

  /**
   * Map Bull job state to JobStatus enum
   */
  private mapJobState(state: string): JobStatus {
    switch (state) {
      case 'pending':
        return JobStatus.PENDING;
      case 'active':
        return JobStatus.ACTIVE;
      case 'completed':
        return JobStatus.COMPLETED;
      case 'failed':
        return JobStatus.FAILED;
      case 'delayed':
        return JobStatus.DELAYED;
      default:
        return JobStatus.PENDING;
    }
  }
}
