import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { SorobanEvent } from '../events/event-listener.service';

export interface FailedEvent extends SorobanEvent {
  error: string;
  failedAt: Date;
  retryCount: number;
}

export interface EventQuery {
  contractId?: string;
  eventName?: string;
  fromLedger?: number;
  toLedger?: number;
  fromTimestamp?: Date;
  toTimestamp?: Date;
  limit?: number;
  offset?: number;
}

@Injectable()
export class StorageService {
  private readonly logger = new Logger(StorageService.name);

  constructor(private readonly prisma: PrismaService) {}

  async storeEvent(eventData: Partial<SorobanEvent>): Promise<any> {
    try {
      const event = await this.prisma.processedEvent.create({
        data: {
          eventId: eventData.id!,
          network: 'stellar',
          ledgerSeq: eventData.ledger!,
          contractId: eventData.contractId!,
          eventType: this.extractEventName(eventData),
          transactionHash: eventData.transactionHash!,
          contractType: (eventData as any).contractType ?? null,
          decodedData: (eventData as any).eventData ?? null,
          abiVersion: (eventData as any).abiVersion ?? null,
        },
      });

      this.logger.debug(`Stored event: ${eventData.transactionHash}`);
      return event;
    } catch (error) {
      this.logger.error(`Error storing event ${eventData.transactionHash}:`, error);
      throw error;
    }
  }

  async eventExists(transactionHash: string): Promise<boolean> {
    try {
      const count = await this.prisma.processedEvent.count({
        where: { transactionHash },
      });
      return count > 0;
    } catch (error) {
      this.logger.error(`Error checking event existence:`, error);
      return false;
    }
  }

  async getEventByTransactionHash(transactionHash: string): Promise<SorobanEvent | null> {
    try {
      const event = await this.prisma.processedEvent.findFirst({
        where: { transactionHash },
      });

      if (!event) return null;

      return {
        id: event.eventId,
        type: 'contract_event',
        contractId: event.contractId,
        topic: [],
        data: JSON.stringify(event.decodedData ?? {}),
        timestamp: new Date().getTime(),
        ledger: event.ledgerSeq,
        transactionHash: event.transactionHash,
      };
    } catch (error) {
      this.logger.error(`Error getting event by hash:`, error);
      return null;
    }
  }

  async getEvents(query: EventQuery): Promise<any[]> {
    try {
      const where: any = {};

      if (query.contractId) {
        where.contractId = query.contractId;
      }

      if (query.eventName) {
        where.eventType = query.eventName;
      }

      if (query.fromLedger) {
        where.ledgerSeq = { gte: query.fromLedger };
      }

      if (query.toLedger) {
        where.ledgerSeq = where.ledgerSeq
          ? { ...where.ledgerSeq, lte: query.toLedger }
          : { lte: query.toLedger };
      }

      const events = await this.prisma.processedEvent.findMany({
        where,
        orderBy: { processedAt: 'desc' },
        take: query.limit,
        skip: query.offset,
      });

      return events;
    } catch (error) {
      this.logger.error('Error querying events:', error);
      throw error;
    }
  }

  async getEventCount(query: Partial<EventQuery>): Promise<number> {
    try {
      const where: any = {};

      if (query.contractId) {
        where.contractId = query.contractId;
      }

      if (query.eventName) {
        where.eventType = query.eventName;
      }

      if (query.fromLedger) {
        where.ledgerSeq = { gte: query.fromLedger };
      }

      if (query.toLedger) {
        where.ledgerSeq = where.ledgerSeq
          ? { ...where.ledgerSeq, lte: query.toLedger }
          : { lte: query.toLedger };
      }

      return await this.prisma.processedEvent.count({ where });
    } catch (error) {
      this.logger.error('Error counting events:', error);
      return 0;
    }
  }

  async getLatestLedger(): Promise<number | null> {
    try {
      const result = await this.prisma.processedEvent.findFirst({
        orderBy: { ledgerSeq: 'desc' },
        select: { ledgerSeq: true },
      });

      return result?.ledgerSeq || null;
    } catch (error) {
      this.logger.error('Error getting latest ledger:', error);
      return null;
    }
  }

  async getLatestCursor(): Promise<string | null> {
    try {
      const result = await this.prisma.ledgerCursor.findFirst({
        orderBy: { updatedAt: 'desc' },
        select: { lastLedgerHash: true },
      });

      return result?.lastLedgerHash || null;
    } catch (error) {
      this.logger.error('Error getting latest cursor:', error);
      return null;
    }
  }

  async storeFailedEvent(failedEvent: FailedEvent): Promise<void> {
    this.logger.error(`Storing failed event: ${failedEvent.transactionHash}`, failedEvent.error);

    // Log the failure
    await this.prisma.indexerLog.create({
      data: {
        level: 'ERROR',
        message: `Failed to process event: ${failedEvent.transactionHash}`,
        metadata: {
          error: failedEvent.error,
          transactionHash: failedEvent.transactionHash,
          retryCount: failedEvent.retryCount,
        },
      },
    });
  }

  async getFailedEvents(limit: number = 100): Promise<FailedEvent[]> {
    const logs = await this.prisma.indexerLog.findMany({
      where: { level: 'ERROR' },
      orderBy: { timestamp: 'desc' },
      take: limit,
    });

    return logs.map((log) => ({
      id: log.id,
      type: 'error',
      contractId: '',
      topic: [],
      data: '',
      timestamp: log.timestamp.getTime(),
      ledger: 0,
      transactionHash: '',
      error: log.message,
      failedAt: log.timestamp,
      retryCount: 0,
    }));
  }

  async getProcessedEventCount(): Promise<number> {
    try {
      return await this.prisma.processedEvent.count();
    } catch (error) {
      this.logger.error('Error getting processed event count:', error);
      return 0;
    }
  }

  async getFailedEventCount(): Promise<number> {
    try {
      return await this.prisma.indexerLog.count({
        where: { level: 'ERROR' },
      });
    } catch (error) {
      this.logger.error('Error getting failed event count:', error);
      return 0;
    }
  }

  async deleteEventsBeforeLedger(ledger: number): Promise<number> {
    try {
      const result = await this.prisma.processedEvent.deleteMany({
        where: { ledgerSeq: { lt: ledger } },
      });

      this.logger.log(`Deleted ${result.count} events before ledger ${ledger}`);
      return result.count;
    } catch (error) {
      this.logger.error(`Error deleting events before ledger ${ledger}:`, error);
      return 0;
    }
  }

  async getEventStatistics(): Promise<{
    totalEvents: number;
    uniqueContracts: number;
    latestLedger: number | null;
    eventsByContract: Array<{ contractId: string; count: number }>;
    eventsByType: Array<{ eventType: string; count: number }>;
  }> {
    try {
      const totalEvents = await this.getProcessedEventCount();

      const uniqueContracts = await this.prisma.processedEvent.groupBy({
        by: ['contractId'],
        _count: true,
      });

      const latestLedger = await this.getLatestLedger();

      const eventsByContract = await this.prisma.processedEvent.groupBy({
        by: ['contractId'],
        _count: true,
        orderBy: { _count: 'desc' },
        take: 10,
      });

      const eventsByType = await this.prisma.processedEvent.groupBy({
        by: ['eventType'],
        _count: true,
        orderBy: { _count: 'desc' },
        take: 10,
      });

      return {
        totalEvents,
        uniqueContracts: uniqueContracts.length,
        latestLedger,
        eventsByContract: eventsByContract.map((group) => ({
          contractId: group.contractId,
          count: group._count,
        })),
        eventsByType: eventsByType.map((group) => ({
          eventType: group.eventType,
          count: group._count,
        })),
      };
    } catch (error) {
      this.logger.error('Error getting event statistics:', error);
      return {
        totalEvents: 0,
        uniqueContracts: 0,
        latestLedger: null,
        eventsByContract: [],
        eventsByType: [],
      };
    }
  }

  async updateEventCursor(transactionHash: string, cursor: string): Promise<boolean> {
    try {
      const result = await this.prisma.ledgerCursor.updateMany({
        where: { network: 'stellar' },
        data: { lastLedgerHash: cursor },
      });

      return result.count > 0;
    } catch (error) {
      this.logger.error(`Error updating event cursor:`, error);
      return false;
    }
  }

  async getEventsByContract(contractId: string, limit: number = 100): Promise<any[]> {
    return this.getEvents({ contractId, limit });
  }

  async getEventsByType(eventName: string, limit: number = 100): Promise<any[]> {
    return this.getEvents({ eventName, limit });
  }

  async getEventsInLedgerRange(fromLedger: number, toLedger: number): Promise<any[]> {
    return this.getEvents({ fromLedger, toLedger });
  }

  private extractEventName(event: Partial<SorobanEvent>): string {
    // Extract event name from event data or use default
    try {
      if ((event as any).eventName) {
        return String((event as any).eventName);
      }
      if (event.data) {
        const parsed = JSON.parse(event.data);
        return parsed.eventName || parsed.name || 'unknown';
      }
    } catch {
      // Ignore parsing errors
    }
    return 'unknown';
  }
}
