import { DomainEvent, EventMetadata } from '../events/event.base';

/**
 * Abstract base class for aggregate roots in event sourcing
 * 
 * Aggregate roots are the consistency boundaries of the domain.
 * They emit events to record state changes and can be reconstructed
 * by replaying those events.
 */
export abstract class AggregateRoot {
  private _id: string;
  private _version: number = 0;
  private _pendingEvents: DomainEvent[] = [];
  private _isReplaying: boolean = false;

  constructor(id: string) {
    this._id = id;
  }

  get id(): string {
    return this._id;
  }

  get version(): number {
    return this._version;
  }

  /**
   * Get pending events that haven't been persisted yet
   */
  getPendingEvents(): DomainEvent[] {
    return [...this._pendingEvents];
  }

  /**
   * Clear pending events after they've been persisted
   */
  clearPendingEvents(): void {
    this._pendingEvents = [];
  }

  /**
   * Apply an event to the aggregate
   * This updates the aggregate state and adds the event to pending events
   */
  protected applyEvent(event: DomainEvent): void {
    // Apply the event to mutate state
    this.when(event);
    
    // Only add to pending events if not replaying
    if (!this._isReplaying) {
      this._pendingEvents.push(event);
    }
    
    this._version = event.version;
  }

  /**
   * Reconstruct the aggregate from a stream of events
   */
  loadFromHistory(events: DomainEvent[]): void {
    this._isReplaying = true;
    
    try {
      for (const event of events) {
        this.when(event);
        this._version = event.version;
      }
    } finally {
      this._isReplaying = false;
    }
  }

  /**
   * Abstract method that must be implemented by concrete aggregates
   * This method mutates the aggregate state based on the event type
   */
  protected abstract when(event: DomainEvent): void;

  /**
   * Create event metadata with correlation and causation tracking
   */
  protected createMetadata(
    correlationId?: string,
    userId?: string
  ): EventMetadata {
    return {
      correlationId: correlationId || crypto.randomUUID(),
      causationId: this._pendingEvents.length > 0 
        ? this._pendingEvents[this._pendingEvents.length - 1].eventId 
        : undefined,
      userId,
      source: 'event-sourcing',
    };
  }

  /**
   * Get the next version number for a new event
   */
  protected nextVersion(): number {
    return this._version + 1;
  }
}
