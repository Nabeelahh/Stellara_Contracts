import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Snapshot } from '../entities/snapshot.entity';
import { AggregateRoot } from '../entities/aggregate-root';

/**
 * Snapshot Service
 * 
 * Manages aggregate snapshots for performance optimization.
 * Snapshots are taken periodically to reduce the number of events
 * that need to be replayed when loading an aggregate.
 */
@Injectable()
export class SnapshotService {
  private readonly logger = new Logger(SnapshotService.name);
  
  // Create snapshot every N events
  private readonly SNAPSHOT_FREQUENCY = 50;

  constructor(
    @InjectRepository(Snapshot)
    private readonly snapshotRepository: Repository<Snapshot>,
  ) {}

  /**
   * Get the latest snapshot for an aggregate
   */
  async getLatestSnapshot(
    aggregateId: string
  ): Promise<Snapshot | null> {
    return this.snapshotRepository.findOne({
      where: { aggregateId },
      order: { version: 'DESC' },
    });
  }

  /**
   * Save a snapshot of an aggregate
   */
  async saveSnapshot(
    aggregate: AggregateRoot,
    aggregateType: string,
    state: Record<string, unknown>
  ): Promise<void> {
    const snapshot = new Snapshot();
    snapshot.aggregateId = aggregate.id;
    snapshot.aggregateType = aggregateType;
    snapshot.version = aggregate.version;
    snapshot.state = state;

    await this.snapshotRepository.save(snapshot);
    
    this.logger.debug(
      `Snapshot saved for ${aggregateType}:${aggregate.id} at version ${aggregate.version}`
    );
  }

  /**
   * Check if a snapshot should be taken
   */
  shouldTakeSnapshot(version: number): boolean {
    return version > 0 && version % this.SNAPSHOT_FREQUENCY === 0;
  }

  /**
   * Delete old snapshots, keeping only the most recent ones
   */
  async cleanupOldSnapshots(
    aggregateId: string,
    keepCount: number = 3
  ): Promise<void> {
    const snapshots = await this.snapshotRepository.find({
      where: { aggregateId },
      order: { version: 'DESC' },
      skip: keepCount,
    });

    if (snapshots.length > 0) {
      await this.snapshotRepository.remove(snapshots);
      this.logger.debug(
        `Cleaned up ${snapshots.length} old snapshots for ${aggregateId}`
      );
    }
  }

  /**
   * Get all snapshots for an aggregate (for debugging/admin)
   */
  async getSnapshotsForAggregate(aggregateId: string): Promise<Snapshot[]> {
    return this.snapshotRepository.find({
      where: { aggregateId },
      order: { version: 'ASC' },
    });
  }
}
