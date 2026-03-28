import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { EventListenerService } from './events/event-listener.service';
import { EventProcessorService } from './processors/event-processor.service';
import { StorageService } from './storage/storage.service';
import { HealthCheckService } from './health/health-check.service';

export interface IndexerConfig {
  stellarHorizonUrl: string;
  contractIds: string[];
  startLedger?: number;
  batchSize: number;
  processingInterval: number;
  enableBackfill: boolean;
}

export interface IndexerStatus {
  isRunning: boolean;
  currentLedger: number;
  latestLedger: number;
  processedEvents: number;
  queueSize: number;
  lastSync: Date;
  health: 'healthy' | 'degraded' | 'unhealthy';
}

@Injectable()
export class IndexerService implements OnModuleInit {
  private readonly logger = new Logger(IndexerService.name);
  private isRunning = false;
  private config: IndexerConfig;

  constructor(
    private eventListener: EventListenerService,
    private eventProcessor: EventProcessorService,
    private storage: StorageService,
    private healthCheck: HealthCheckService,
  ) {}

  async onModuleInit(): Promise<void> {
    this.config = this.loadConfig();
    this.logger.log('Indexer service initialized');
  }

  async startIndexer(config?: Partial<IndexerConfig>): Promise<void> {
    if (this.isRunning) {
      this.logger.warn('Indexer is already running');
      return;
    }

    if (config) {
      this.config = { ...this.config, ...config };
    }

    this.logger.log('Starting indexer service...');

    try {
      // Start event listener
      await this.eventListener.startListening(this.config.contractIds);

      this.isRunning = true;
      this.logger.log('Indexer service started successfully');

      // Perform initial backfill if enabled
      if (this.config.enableBackfill && this.config.startLedger) {
        await this.performInitialBackfill();
      }
    } catch (error) {
      this.logger.error('Failed to start indexer:', error);
      this.isRunning = false;
      throw error;
    }
  }

  async stopIndexer(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    this.logger.log('Stopping indexer service...');

    try {
      await this.eventListener.stopListening();
      this.isRunning = false;
      this.logger.log('Indexer service stopped');
    } catch (error) {
      this.logger.error('Error stopping indexer:', error);
      throw error;
    }
  }

  async getStatus(): Promise<IndexerStatus> {
    const health = await this.healthCheck.getHealthStatus();
    const latestLedger = await this.storage.getLatestLedger();
    const stats = await this.getProcessingStats();

    return {
      isRunning: this.isRunning,
      currentLedger: latestLedger || 0,
      latestLedger: health.sync.latestLedger,
      processedEvents: stats.processedCount,
      queueSize: stats.queueSize,
      lastSync: new Date(),
      health: health.status,
    };
  }

  async backfillEvents(
    fromLedger: number,
    toLedger?: number,
    contractIds?: string[],
  ): Promise<{ processed: number; errors: number }> {
    this.logger.log(`Starting backfill from ledger ${fromLedger} to ${toLedger || 'latest'}`);

    try {
      const events = await this.eventListener.backfillEvents(
        fromLedger,
        toLedger,
        contractIds || this.config.contractIds,
      );

      let processed = 0;
      let errors = 0;

      for (const event of events) {
        try {
          await this.eventProcessor.addToQueue(event);
          processed++;
        } catch (error) {
          this.logger.error(`Error processing backfill event ${event.id}:`, error);
          errors++;
        }
      }

      this.logger.log(`Backfill completed: ${processed} processed, ${errors} errors`);
      return { processed, errors };
    } catch (error) {
      this.logger.error('Backfill failed:', error);
      throw error;
    }
  }

  async reprocessEvent(transactionHash: string): Promise<void> {
    this.logger.log(`Reprocessing event: ${transactionHash}`);

    try {
      await this.eventProcessor.reprocessEvent(transactionHash);
      this.logger.log(`Event reprocessed successfully: ${transactionHash}`);
    } catch (error) {
      this.logger.error(`Failed to reprocess event ${transactionHash}:`, error);
      throw error;
    }
  }

  async getEventStatistics(): Promise<any> {
    return await this.storage.getEventStatistics();
  }

  async getHealthReport(): Promise<any> {
    return await this.healthCheck.getDetailedHealthReport();
  }

  private async performInitialBackfill(): Promise<void> {
    if (!this.config.startLedger) {
      return;
    }

    const latestLedger = await this.storage.getLatestLedger();

    if (latestLedger && latestLedger >= this.config.startLedger) {
      this.logger.log(`Skipping backfill - already at ledger ${latestLedger}`);
      return;
    }

    this.logger.log(`Performing initial backfill from ledger ${this.config.startLedger}`);

    try {
      await this.backfillEvents(this.config.startLedger, latestLedger || undefined);
    } catch (error) {
      this.logger.error('Initial backfill failed:', error);
      // Don't throw - indexer can still start for new events
    }
  }

  private async getProcessingStats(): Promise<{
    queueSize: number;
    processedCount: number;
    failedCount: number;
    isProcessing: boolean;
  }> {
    // This would be implemented in the processor service
    return {
      queueSize: 0,
      processedCount: 0,
      failedCount: 0,
      isProcessing: false,
    };
  }

  private loadConfig(): IndexerConfig {
    return {
      stellarHorizonUrl: process.env.STELLAR_HORIZON_URL || 'https://horizon.stellar.org',
      contractIds: process.env.CONTRACT_IDS?.split(',') || [],
      startLedger: process.env.START_LEDGER ? parseInt(process.env.START_LEDGER) : undefined,
      batchSize: parseInt(process.env.BATCH_SIZE || '100'),
      processingInterval: parseInt(process.env.PROCESSING_INTERVAL || '1000'),
      enableBackfill: process.env.ENABLE_BACKFILL === 'true',
    };
  }

  updateConfig(config: Partial<IndexerConfig>): void {
    this.config = { ...this.config, ...config };
    this.logger.log('Indexer configuration updated');
  }

  getConfig(): IndexerConfig {
    return { ...this.config };
  }

  isIndexerRunning(): boolean {
    return this.isRunning;
  }
}
