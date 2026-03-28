import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, QueryRunner } from 'typeorm';
import { StoredEvent } from '../entities/stored-event.entity';
import { DomainEvent, EventMetadata } from '../events/event.base';

/**
 * Event Store Service
 * 
 * Implements the event store pattern using PostgreSQL.
 * Provides append-only storage for domain events with optimistic concurrency control.
 */
@Injectable()
export class EventStoreService {
  private readonly logger = new Logger(EventStoreService.name);

  constructor(
    @InjectRepository(StoredEvent)
    private readonly eventRepository: Repository<StoredEvent>,
    private readonly dataSource: DataSource,
  ) {}

  /**
   * Append a single event to the store
   * Uses optimistic concurrency control based on aggregate version
   */
  async appendEvent(event: DomainEvent): Promise<void> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Check for concurrent modification
      const latestEvent = await queryRunner.manager.findOne(StoredEvent, {
        where: { aggregateId: event.aggregateId },
        order: { version: 'DESC' },
      });

      const expectedVersion = latestEvent ? latestEvent.version : 0;
      
      if (event.version !== expectedVersion + 1) {
        throw new Error(
          `Concurrent modification detected for aggregate ${event.aggregateId}. ` +
          `Expected version: ${expectedVersion + 1}, got: ${event.version}`
        );
      }

      const storedEvent = this.mapToStoredEvent(event);
      await queryRunner.manager.save(StoredEvent, storedEvent);
      
      await queryRunner.commitTransaction();
      
      this.logger.debug(
        `Event ${event.eventType} appended for aggregate ${event.aggregateId} at version ${event.version}`
      );
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to append event for aggregate ${event.aggregateId}: ${error.message}`
      );
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Append multiple events atomically
   */
  async appendEvents(events: DomainEvent[]): Promise<void> {
    if (events.length === 0) return;

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Group events by aggregate for version checking
      const eventsByAggregate = this.groupEventsByAggregate(events);

      for (const [aggregateId, aggregateEvents] of eventsByAggregate) {
        const latestEvent = await queryRunner.manager.findOne(StoredEvent, {
          where: { aggregateId },
          order: { version: 'DESC' },
        });

        let expectedVersion = latestEvent ? latestEvent.version : 0;

        for (const event of aggregateEvents) {
          if (event.version !== expectedVersion + 1) {
            throw new Error(
              `Concurrent modification detected for aggregate ${aggregateId}. ` +
              `Expected version: ${expectedVersion + 1}, got: ${event.version}`
            );
          }
          expectedVersion = event.version;
        }
      }

      // Save all events
      const storedEvents = events.map(event => this.mapToStoredEvent(event));
      await queryRunner.manager.save(StoredEvent, storedEvents);
      
      await queryRunner.commitTransaction();
      
      this.logger.debug(
        `Batch of ${events.length} events appended successfully`
      );
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(`Failed to append events batch: ${error.message}`);
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Get all events for an aggregate ordered by version
   */
  async getEventsForAggregate(aggregateId: string): Promise<StoredEvent[]> {
    return this.eventRepository.find({
      where: { aggregateId },
      order: { version: 'ASC' },
    });
  }

  /**
   * Get events for an aggregate from a specific version
   */
  async getEventsFromVersion(
    aggregateId: string,
    fromVersion: number
  ): Promise<StoredEvent[]> {
    return this.eventRepository.find({
      where: { aggregateId, version: fromVersion },
      order: { version: 'ASC' },
    });
  }

  /**
   * Get the current version of an aggregate
   */
  async getCurrentVersion(aggregateId: string): Promise<number> {
    const event = await this.eventRepository.findOne({
      where: { aggregateId },
      order: { version: 'DESC' },
    });
    return event ? event.version : 0;
  }

  /**
   * Get events by type within a time range
   */
  async getEventsByType(
    eventType: string,
    from: Date,
    to: Date
  ): Promise<StoredEvent[]> {
    return this.eventRepository
      .createQueryBuilder('event')
      .where('event.eventType = :eventType', { eventType })
      .andWhere('event.occurredAt BETWEEN :from AND :to', { from, to })
      .orderBy('event.occurredAt', 'ASC')
      .getMany();
  }

  /**
   * Get all events after a specific timestamp (for projections)
   */
  async getEventsAfter(timestamp: Date, limit: number = 100): Promise<StoredEvent[]> {
    return this.eventRepository.find({
      where: { occurredAt: timestamp },
      order: { occurredAt: 'ASC' },
      take: limit,
    });
  }

  /**
   * Replay all events for rebuilding projections
   */
  async replayAllEvents(
    batchSize: number = 1000,
    onBatch?: (events: StoredEvent[]) => Promise<void>
  ): Promise<void> {
    let offset = 0;
    let hasMore = true;

    while (hasMore) {
      const events = await this.eventRepository.find({
        order: { occurredAt: 'ASC', version: 'ASC' },
        skip: offset,
        take: batchSize,
      });

      if (events.length === 0) {
        hasMore = false;
      } else {
        if (onBatch) {
          await onBatch(events);
        }
        offset += events.length;
        this.logger.debug(`Replayed ${offset} events so far...`);
      }
    }
  }

  /**
   * Map domain event to stored event entity
   */
  private mapToStoredEvent(event: DomainEvent): StoredEvent {
    const stored = new StoredEvent();
    stored.eventId = event.eventId;
    stored.aggregateId = event.aggregateId;
    stored.aggregateType = this.extractAggregateType(event.eventType);
    stored.eventType = event.eventType;
    stored.version = event.version;
    stored.payload = event.payload;
    stored.metadata = event.metadata;
    stored.schemaVersion = event.schemaVersion;
    stored.occurredAt = event.occurredAt;
    stored.correlationId = event.metadata.correlationId || '';
    stored.causationId = event.metadata.causationId || '';
    stored.userId = event.metadata.userId || '';
    stored.source = event.metadata.source;
    return stored;
  }

  /**
   * Extract aggregate type from event type
   */
  private extractAggregateType(eventType: string): string {
    // Remove "Event" suffix and derive aggregate type
    // e.g., "UserRegistered" -> "User"
    // e.g., "TradeExecuted" -> "Trade"
    const match = eventType.match(/^(\w+?)(Registered|Updated|Changed|Deposited|Withdrawn|Executed|Placed|Cancelled|Filled|Reserved|Released)/);
    return match ? match[1] : 'Unknown';
  }

  /**
   * Group events by aggregate ID
   */
  private groupEventsByAggregate(
    events: DomainEvent[]
  ): Map<string, DomainEvent[]> {
    const grouped = new Map<string, DomainEvent[]>();
    
    for (const event of events) {
      const list = grouped.get(event.aggregateId) || [];
      list.push(event);
      grouped.set(event.aggregateId, list);
    }

    // Sort each group by version
    for (const [, list] of grouped) {
      list.sort((a, b) => a.version - b.version);
    }

    return grouped;
  }
}
