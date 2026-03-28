import { Injectable, Logger } from '@nestjs/common';
import { EventStoreService } from './event-store.service';
import { SnapshotService } from '../snapshots/snapshot.service';
import { EventBusService } from './event-bus.service';
import { AggregateRoot } from '../entities/aggregate-root';
import { StoredEvent } from '../entities/stored-event.entity';
import { DomainEvent } from '../events/event.base';

/**
 * Event Sourced Repository
 * 
 * Base class for repositories that use event sourcing.
 * Provides methods for loading and saving aggregates.
 */
@Injectable()
export abstract class EventSourcedRepository<
  T extends AggregateRoot,
> {
  private readonly logger = new Logger(EventSourcedRepository.name);

  constructor(
    protected readonly eventStore: EventStoreService,
    protected readonly snapshotService: SnapshotService,
    protected readonly eventBus: EventBusService,
  ) {}

  /**
   * Find an aggregate by ID
   * Loads from snapshot if available, then applies remaining events
   */
  async findById(aggregateId: string): Promise<T | null> {
    // Try to load from snapshot first
    const snapshot = await this.snapshotService.getLatestSnapshot(aggregateId);
    
    let aggregate: T;
    let fromVersion = 0;

    if (snapshot) {
      // Reconstruct from snapshot
      aggregate = this.createFromSnapshot(snapshot.state);
      fromVersion = snapshot.version + 1;
      
      this.logger.debug(
        `Loaded ${this.getAggregateType()}:${aggregateId} from snapshot at version ${snapshot.version}`
      );
    }

    // Load remaining events
    const events = await this.eventStore.getEventsFromVersion(
      aggregateId,
      fromVersion
    );

    if (events.length === 0 && !snapshot) {
      return null; // Aggregate doesn't exist
    }

    if (!aggregate!) {
      // No snapshot, create new aggregate
      aggregate = this.createNew(aggregateId);
    }

    // Apply remaining events
    if (events.length > 0) {
      const domainEvents = events.map(e => this.toDomainEvent(e));
      aggregate.loadFromHistory(domainEvents);
      
      this.logger.debug(
        `Applied ${events.length} events to ${this.getAggregateType()}:${aggregateId}`
      );
    }

    return aggregate;
  }

  /**
   * Save an aggregate
   * Persists pending events and publishes them to the event bus
   */
  async save(aggregate: T): Promise<void> {
    const pendingEvents = aggregate.getPendingEvents();

    if (pendingEvents.length === 0) {
      return; // Nothing to save
    }

    // Append events to store
    await this.eventStore.appendEvents(pendingEvents);

    // Publish events to bus
    await this.eventBus.publishAll(pendingEvents);

    // Clear pending events
    aggregate.clearPendingEvents();

    // Take snapshot if needed
    const lastEvent = pendingEvents[pendingEvents.length - 1];
    if (this.snapshotService.shouldTakeSnapshot(lastEvent.version)) {
      const state = this.toSnapshotState(aggregate);
      await this.snapshotService.saveSnapshot(
        aggregate,
        this.getAggregateType(),
        state
      );
    }

    this.logger.debug(
      `Saved ${this.getAggregateType()}:${aggregate.id} with ${pendingEvents.length} events`
    );
  }

  /**
   * Check if an aggregate exists
   */
  async exists(aggregateId: string): Promise<boolean> {
    const version = await this.eventStore.getCurrentVersion(aggregateId);
    return version > 0;
  }

  /**
   * Get the current version of an aggregate
   */
  async getVersion(aggregateId: string): Promise<number> {
    return this.eventStore.getCurrentVersion(aggregateId);
  }

  /**
   * Abstract method to create a new aggregate instance
   */
  protected abstract createNew(aggregateId: string): T;

  /**
   * Abstract method to create aggregate from snapshot state
   */
  protected abstract createFromSnapshot(state: Record<string, unknown>): T;

  /**
   * Abstract method to convert aggregate to snapshot state
   */
  protected abstract toSnapshotState(aggregate: T): Record<string, unknown>;

  /**
   * Abstract method to convert stored event to domain event
   */
  protected abstract toDomainEvent(storedEvent: StoredEvent): DomainEvent;

  /**
   * Get the aggregate type name
   */
  protected abstract getAggregateType(): string;
}
