import { Injectable, Logger } from '@nestjs/common';
import { Subject, Observable, filter } from 'rxjs';
import { DomainEvent } from '../events/event.base';

/**
 * Event Handler Interface
 */
export interface EventHandler<T extends DomainEvent = DomainEvent> {
  handle(event: T): Promise<void>;
  eventTypes: string[];
}

/**
 * Event Bus Service
 * 
 * Implements pub/sub pattern for domain events.
 * Used to publish events to projections and other subscribers.
 */
@Injectable()
export class EventBusService {
  private readonly logger = new Logger(EventBusService.name);
  private readonly eventStream = new Subject<DomainEvent>();
  private readonly handlers = new Map<string, EventHandler[]>();

  /**
   * Subscribe to all events
   */
  subscribe(): Observable<DomainEvent> {
    return this.eventStream.asObservable();
  }

  /**
   * Subscribe to specific event types
   */
  subscribeTo(eventTypes: string[]): Observable<DomainEvent> {
    return this.eventStream.pipe(
      filter(event => eventTypes.includes(event.eventType))
    );
  }

  /**
   * Publish a single event
   */
  async publish(event: DomainEvent): Promise<void> {
    this.logger.debug(`Publishing event: ${event.eventType}`);
    
    // Emit to RxJS stream
    this.eventStream.next(event);
    
    // Call registered handlers
    await this.callHandlers(event);
  }

  /**
   * Publish multiple events
   */
  async publishAll(events: DomainEvent[]): Promise<void> {
    for (const event of events) {
      await this.publish(event);
    }
  }

  /**
   * Register an event handler
   */
  register(handler: EventHandler): void {
    for (const eventType of handler.eventTypes) {
      const handlers = this.handlers.get(eventType) || [];
      handlers.push(handler);
      this.handlers.set(eventType, handlers);
      
      this.logger.log(
        `Registered handler ${handler.constructor.name} for event ${eventType}`
      );
    }
  }

  /**
   * Unregister an event handler
   */
  unregister(handler: EventHandler): void {
    for (const eventType of handler.eventTypes) {
      const handlers = this.handlers.get(eventType) || [];
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
        this.handlers.set(eventType, handlers);
      }
    }
  }

  /**
   * Call all registered handlers for an event
   */
  private async callHandlers(event: DomainEvent): Promise<void> {
    const handlers = this.handlers.get(event.eventType) || [];
    
    const promises = handlers.map(async handler => {
      try {
        await handler.handle(event);
      } catch (error) {
        this.logger.error(
          `Handler ${handler.constructor.name} failed for event ${event.eventType}: ${error.message}`
        );
        // Don't throw - we want other handlers to continue
      }
    });

    await Promise.all(promises);
  }
}
