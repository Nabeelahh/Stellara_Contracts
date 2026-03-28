import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EventStoreService } from './store/event-store.service';
import { EventBusService } from './store/event-bus.service';
import { SnapshotService } from './snapshots/snapshot.service';
import { StoredEvent } from './entities/stored-event.entity';
import { Snapshot } from './entities/snapshot.entity';

/**
 * Event Sourcing Module
 * 
 * Provides event sourcing infrastructure including:
 * - Event store for persisting domain events
 * - Event bus for publishing events to projections
 * - Snapshot service for performance optimization
 */
@Module({
  imports: [TypeOrmModule.forFeature([StoredEvent, Snapshot])],
  providers: [
    EventStoreService,
    EventBusService,
    SnapshotService,
  ],
  exports: [
    EventStoreService,
    EventBusService,
    SnapshotService,
  ],
})
export class EventSourcingModule {}
