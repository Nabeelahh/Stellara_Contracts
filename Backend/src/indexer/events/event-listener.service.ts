import { Injectable, Logger } from '@nestjs/common';
import { EventEmitter } from 'events';
import { StellarSdk } from 'stellar-sdk';

export interface SorobanEvent {
  id: string;
  type: string;
  contractId: string;
  topic: string[];
  data: string;
  timestamp: number;
  ledger: number;
  transactionHash: string;
}

export interface EventFilter {
  contractId?: string;
  eventName?: string;
  fromLedger?: number;
  toLedger?: number;
}

export interface CursorCheckpoint {
  ledger: number;
  cursor: string;
  timestamp: Date;
}

@Injectable()
export class EventListenerService extends EventEmitter {
  private readonly logger = new Logger(EventListenerService.name);
  private stellarServer: StellarSdk.Server;
  private isListening = false;
  private currentCursor: string | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 5000; // 5 seconds

  constructor() {
    super();
    this.stellarServer = new StellarSdk.Server(
      process.env.STELLAR_HORIZON_URL || 'https://horizon.stellar.org',
      { allowHttp: false },
    );
  }

  async startListening(contractIds: string[] = []): Promise<void> {
    if (this.isListening) {
      this.logger.warn('Event listener is already running');
      return;
    }

    this.logger.log('Starting blockchain event listener...');
    this.isListening = true;

    try {
      // Get the latest checkpoint
      const checkpoint = await this.getLatestCheckpoint();
      this.currentCursor = checkpoint?.cursor || 'now';

      // Start streaming events
      await this.streamEvents(contractIds);
    } catch (error) {
      this.logger.error('Failed to start event listener:', error);
      this.isListening = false;
      throw error;
    }
  }

  async stopListening(): Promise<void> {
    if (!this.isListening) {
      return;
    }

    this.logger.log('Stopping blockchain event listener...');
    this.isListening = false;

    // Close any active connections
    if (this.stellarServer) {
      // In a real implementation, properly close the connection
    }
  }

  async backfillEvents(
    fromLedger: number,
    toLedger?: number,
    contractIds: string[] = [],
  ): Promise<SorobanEvent[]> {
    this.logger.log(`Backfilling events from ledger ${fromLedger} to ${toLedger || 'latest'}`);

    const events: SorobanEvent[] = [];
    let cursor = this.buildLedgerCursor(fromLedger);

    try {
      while (true) {
        const response = await this.stellarServer
          .transactions()
          .cursor(cursor)
          .limit(200)
          .order('asc')
          .call();

        if (response.records.length === 0) {
          break;
        }

        const transactionEvents = await this.extractEventsFromTransactions(
          response.records,
          contractIds,
        );

        events.push(...transactionEvents);

        // Check if we've reached the target ledger
        const lastLedger = response.records[response.records.length - 1].ledger;
        if (toLedger && lastLedger >= toLedger) {
          break;
        }

        cursor = response.cursor;
      }

      this.logger.log(`Backfilled ${events.length} events`);
      return events;
    } catch (error) {
      this.logger.error('Error during backfill:', error);
      throw error;
    }
  }

  private async streamEvents(contractIds: string[]): Promise<void> {
    while (this.isListening) {
      try {
        const callBuilder = this.stellarServer.transactions();

        if (this.currentCursor) {
          callBuilder.cursor(this.currentCursor);
        }

        const response = await callBuilder.limit(100).order('asc').call();

        if (response.records.length > 0) {
          const events = await this.extractEventsFromTransactions(response.records, contractIds);

          // Emit events for processing
          events.forEach((event) => {
            this.emit('sorobanEvent', event);
          });

          // Update cursor
          this.currentCursor = response.cursor;
          await this.saveCheckpoint(response.records[response.records.length - 1]);

          // Reset reconnect attempts on successful processing
          this.reconnectAttempts = 0;
        }

        // Wait before next poll
        await this.sleep(1000); // 1 second
      } catch (error) {
        this.logger.error('Error in event stream:', error);
        await this.handleStreamError(error);
      }
    }
  }

  private async extractEventsFromTransactions(
    transactions: any[],
    contractIds: string[],
  ): Promise<SorobanEvent[]> {
    const events: SorobanEvent[] = [];

    for (const tx of transactions) {
      if (!tx.operations || !tx.operations.length) {
        continue;
      }

      for (const op of tx.operations) {
        if (op.type === 'invoke_host_function' && op.value?.effects) {
          const sorobanEvents = this.parseSorobanEvents(op.value.effects, tx, contractIds);
          events.push(...sorobanEvents);
        }
      }
    }

    return events;
  }

  private parseSorobanEvents(
    effects: any[],
    transaction: any,
    contractIds: string[],
  ): SorobanEvent[] {
    const events: SorobanEvent[] = [];

    for (const effect of effects) {
      if (effect.type === 'contract_event' || effect.type === 'diagnostic_event') {
        const event = this.parseContractEvent(effect, transaction, contractIds);
        if (event) {
          events.push(event);
        }
      }
    }

    return events;
  }

  private parseContractEvent(
    effect: any,
    transaction: any,
    contractIds: string[],
  ): SorobanEvent | null {
    try {
      const contractId = effect.contract_id || effect.value?.contract_id;

      // Filter by contract IDs if specified
      if (contractIds.length > 0 && !contractIds.includes(contractId)) {
        return null;
      }

      const event: SorobanEvent = {
        id: this.generateEventId(effect, transaction),
        type: effect.type,
        contractId,
        topic: effect.topic || [],
        data: effect.value?.data || effect.data || '',
        timestamp: new Date(transaction.created_at).getTime(),
        ledger: transaction.ledger,
        transactionHash: transaction.hash,
      };

      return event;
    } catch (error) {
      this.logger.error('Error parsing contract event:', error);
      return null;
    }
  }

  private async handleStreamError(error: any): Promise<void> {
    this.reconnectAttempts++;

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.logger.error('Max reconnection attempts reached. Stopping listener.');
      this.isListening = false;
      return;
    }

    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    this.logger.warn(
      `Reconnection attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`,
    );

    await this.sleep(delay);
  }

  private async saveCheckpoint(lastTransaction: any): Promise<void> {
    try {
      const checkpoint: CursorCheckpoint = {
        ledger: lastTransaction.ledger,
        cursor: lastTransaction.paging_token,
        timestamp: new Date(),
      };

      // Save checkpoint to database (mock implementation)
      this.logger.debug(`Saved checkpoint at ledger ${checkpoint.ledger}`);
    } catch (error) {
      this.logger.error('Error saving checkpoint:', error);
    }
  }

  private async getLatestCheckpoint(): Promise<CursorCheckpoint | null> {
    try {
      // Get checkpoint from database (mock implementation)
      return null;
    } catch (error) {
      this.logger.error('Error getting latest checkpoint:', error);
      return null;
    }
  }

  private buildLedgerCursor(ledger: number): string {
    // In a real implementation, this would build a proper cursor
    return `ledger:${ledger}`;
  }

  private generateEventId(effect: any, transaction: any): string {
    return `${transaction.hash}_${effect.id || Date.now()}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  getCurrentCursor(): string | null {
    return this.currentCursor;
  }

  isRunning(): boolean {
    return this.isListening;
  }

  getReconnectStatus(): {
    attempts: number;
    maxAttempts: number;
    delay: number;
  } {
    return {
      attempts: this.reconnectAttempts,
      maxAttempts: this.maxReconnectAttempts,
      delay: this.reconnectDelay,
    };
  }
}
