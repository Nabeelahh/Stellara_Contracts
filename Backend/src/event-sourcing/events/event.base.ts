/**
 * Base interface for all domain events
 * All events must implement this interface
 */
export interface DomainEvent {
  /** Unique event ID */
  readonly eventId: string;
  
  /** Aggregate ID (the entity this event belongs to) */
  readonly aggregateId: string;
  
  /** Event type - used for deserialization and routing */
  readonly eventType: string;
  
  /** Version of the aggregate after this event is applied */
  readonly version: number;
  
  /** Timestamp when the event occurred */
  readonly occurredAt: Date;
  
  /** Event schema version for upcasting support */
  readonly schemaVersion: number;
  
  /** Event payload - the actual event data */
  readonly payload: Record<string, unknown>;
  
  /** Metadata (correlation ID, causation ID, user ID, etc.) */
  readonly metadata: EventMetadata;
}

/**
 * Metadata attached to every event
 */
export interface EventMetadata {
  /** Correlation ID for tracing requests across services */
  correlationId: string;
  
  /** Causation ID - the event that caused this event */
  causationId?: string;
  
  /** User who triggered the event */
  userId?: string;
  
  /** Service that emitted the event */
  source: string;
  
  /** Additional custom metadata */
  [key: string]: unknown;
}

/**
 * Abstract base class for domain events
 */
export abstract class BaseDomainEvent implements DomainEvent {
  readonly eventId: string;
  readonly aggregateId: string;
  readonly eventType: string;
  readonly version: number;
  readonly occurredAt: Date;
  readonly schemaVersion: number;
  readonly metadata: EventMetadata;
  abstract readonly payload: Record<string, unknown>;

  constructor(
    aggregateId: string,
    eventType: string,
    version: number,
    metadata: EventMetadata,
    eventId?: string,
    occurredAt?: Date,
    schemaVersion: number = 1,
  ) {
    this.eventId = eventId || crypto.randomUUID();
    this.aggregateId = aggregateId;
    this.eventType = eventType;
    this.version = version;
    this.occurredAt = occurredAt || new Date();
    this.schemaVersion = schemaVersion;
    this.metadata = metadata;
  }
}
