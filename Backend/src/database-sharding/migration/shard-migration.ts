import { Injectable, Logger } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ShardNode } from '../hashing/consistent-hash';

/**
 * Migration Status
 */
export enum MigrationStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed',
  ROLLED_BACK = 'rolled_back',
}

/**
 * Migration Job
 */
export interface MigrationJob {
  id: string;
  sourceShardId: string;
  targetShardId: string;
  status: MigrationStatus;
  keysToMigrate: string[];
  keysMigrated: string[];
  keysFailed: string[];
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
  progress: number; // 0-100
}

/**
 * Migration Plan
 */
export interface MigrationPlan {
  sourceShard: ShardNode;
  targetShard: ShardNode;
  keys: string[];
  estimatedSize: number;
  estimatedDuration: number; // seconds
}

/**
 * Shard Migration Service
 * 
 * Handles zero-downtime migration of data between shards.
 * Uses a two-phase approach: copy + verify + switchover.
 */
@Injectable()
export class ShardMigrationService {
  private readonly logger = new Logger(ShardMigrationService.name);
  private activeMigrations: Map<string, MigrationJob> = new Map();
  private readonly BATCH_SIZE = 1000;

  constructor(private readonly eventEmitter: EventEmitter2) {}

  /**
   * Create a migration plan for splitting a shard
   */
  async createSplitPlan(
    sourceShard: ShardNode,
    targetShard: ShardNode,
    keySelector: (key: string) => boolean
  ): Promise<MigrationPlan> {
    // Get all keys from source shard
    const allKeys = await this.getAllKeysFromShard(sourceShard);
    
    // Filter keys to migrate based on selector
    const keysToMigrate = allKeys.filter(keySelector);
    
    // Estimate size
    const estimatedSize = await this.estimateMigrationSize(sourceShard, keysToMigrate);
    
    // Estimate duration (rough calculation: 1000 keys per second)
    const estimatedDuration = Math.ceil(keysToMigrate.length / this.BATCH_SIZE);

    return {
      sourceShard,
      targetShard,
      keys: keysToMigrate,
      estimatedSize,
      estimatedDuration,
    };
  }

  /**
   * Start a migration job
   */
  async startMigration(plan: MigrationPlan): Promise<MigrationJob> {
    const jobId = `migration-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const job: MigrationJob = {
      id: jobId,
      sourceShardId: plan.sourceShard.id,
      targetShardId: plan.targetShard.id,
      status: MigrationStatus.PENDING,
      keysToMigrate: plan.keys,
      keysMigrated: [],
      keysFailed: [],
      progress: 0,
    };

    this.activeMigrations.set(jobId, job);
    
    // Start migration asynchronously
    this.executeMigration(job, plan).catch(error => {
      this.logger.error(`Migration ${jobId} failed: ${error.message}`);
      job.status = MigrationStatus.FAILED;
      job.error = error.message;
      this.emitMigrationEvent('failed', job);
    });

    this.logger.log(`Started migration ${jobId}: ${plan.keys.length} keys from ${plan.sourceShard.id} to ${plan.targetShard.id}`);
    
    return job;
  }

  /**
   * Execute the migration
   */
  private async executeMigration(
    job: MigrationJob,
    plan: MigrationPlan
  ): Promise<void> {
    job.status = MigrationStatus.IN_PROGRESS;
    job.startedAt = new Date();
    
    this.emitMigrationEvent('started', job);

    try {
      // Phase 1: Initial bulk copy
      await this.phase1BulkCopy(job, plan);
      
      // Phase 2: Catch-up sync (for changes during bulk copy)
      await this.phase2CatchUpSync(job, plan);
      
      // Phase 3: Verify data integrity
      const verified = await this.phase3Verify(job, plan);
      
      if (!verified) {
        throw new Error('Data verification failed');
      }
      
      // Phase 4: Switchover (atomic cutover)
      await this.phase4Switchover(job, plan);
      
      job.status = MigrationStatus.COMPLETED;
      job.completedAt = new Date();
      job.progress = 100;
      
      this.emitMigrationEvent('completed', job);
      this.logger.log(`Migration ${job.id} completed successfully`);
      
    } catch (error) {
      job.status = MigrationStatus.FAILED;
      job.error = error.message;
      this.emitMigrationEvent('failed', job);
      
      // Attempt rollback
      await this.rollbackMigration(job, plan);
      
      throw error;
    }
  }

  /**
   * Phase 1: Bulk copy data from source to target
   */
  private async phase1BulkCopy(
    job: MigrationJob,
    plan: MigrationPlan
  ): Promise<void> {
    this.logger.debug(`Phase 1: Bulk copy for migration ${job.id}`);
    
    const batches = this.chunkArray(job.keysToMigrate, this.BATCH_SIZE);
    
    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      
      try {
        // Copy batch from source to target
        await this.copyBatch(plan.sourceShard, plan.targetShard, batch);
        
        job.keysMigrated.push(...batch);
        job.progress = Math.floor((job.keysMigrated.length / job.keysToMigrate.length) * 80);
        
        this.emitMigrationEvent('progress', job);
        
      } catch (error) {
        this.logger.error(`Failed to copy batch ${i}: ${error.message}`);
        job.keysFailed.push(...batch);
      }
    }
  }

  /**
   * Phase 2: Catch-up sync for changes during bulk copy
   */
  private async phase2CatchUpSync(
    job: MigrationJob,
    plan: MigrationPlan
  ): Promise<void> {
    this.logger.debug(`Phase 2: Catch-up sync for migration ${job.id}`);
    
    // Get changes since bulk copy started
    const changes = await this.getChangesSince(plan.sourceShard, job.startedAt!);
    
    // Apply changes to target
    for (const change of changes) {
      if (job.keysToMigrate.includes(change.key)) {
        await this.applyChange(plan.targetShard, change);
      }
    }
    
    job.progress = 90;
    this.emitMigrationEvent('progress', job);
  }

  /**
   * Phase 3: Verify data integrity
   */
  private async phase3Verify(
    job: MigrationJob,
    plan: MigrationPlan
  ): Promise<boolean> {
    this.logger.debug(`Phase 3: Verification for migration ${job.id}`);
    
    // Sample verification (check 10% of keys)
    const sampleSize = Math.max(100, Math.floor(job.keysMigrated.length * 0.1));
    const sample = this.sampleArray(job.keysMigrated, sampleSize);
    
    let verified = 0;
    let failed = 0;
    
    for (const key of sample) {
      const sourceData = await this.getData(plan.sourceShard, key);
      const targetData = await this.getData(plan.targetShard, key);
      
      if (this.compareData(sourceData, targetData)) {
        verified++;
      } else {
        failed++;
        this.logger.warn(`Verification failed for key: ${key}`);
      }
    }
    
    const successRate = verified / (verified + failed);
    this.logger.log(`Verification complete: ${successRate * 100}% success rate`);
    
    job.progress = 95;
    this.emitMigrationEvent('progress', job);
    
    return successRate > 0.99; // 99% success threshold
  }

  /**
   * Phase 4: Atomic switchover
   */
  private async phase4Switchover(
    job: MigrationJob,
    plan: MigrationPlan
  ): Promise<void> {
    this.logger.debug(`Phase 4: Switchover for migration ${job.id}`);
    
    // Enable write blocking on source shard
    await this.enableWriteBlocking(plan.sourceShard);
    
    // Final sync of any remaining changes
    const finalChanges = await this.getChangesSince(plan.sourceShard, new Date(Date.now() - 5000));
    for (const change of finalChanges) {
      if (job.keysToMigrate.includes(change.key)) {
        await this.applyChange(plan.targetShard, change);
      }
    }
    
    // Update routing to point to new shard
    await this.updateRouting(job.keysToMigrate, plan.targetShard.id);
    
    // Disable write blocking
    await this.disableWriteBlocking(plan.sourceShard);
    
    job.progress = 100;
    this.emitMigrationEvent('switchover', job);
  }

  /**
   * Rollback a failed migration
   */
  private async rollbackMigration(
    job: MigrationJob,
    plan: MigrationPlan
  ): Promise<void> {
    this.logger.warn(`Rolling back migration ${job.id}`);
    
    try {
      // Delete migrated data from target
      for (const key of job.keysMigrated) {
        await this.deleteData(plan.targetShard, key);
      }
      
      job.status = MigrationStatus.ROLLED_BACK;
      this.emitMigrationEvent('rolled_back', job);
      
    } catch (error) {
      this.logger.error(`Rollback failed: ${error.message}`);
    }
  }

  /**
   * Get migration status
   */
  getMigrationStatus(jobId: string): MigrationJob | undefined {
    return this.activeMigrations.get(jobId);
  }

  /**
   * Get all active migrations
   */
  getActiveMigrations(): MigrationJob[] {
    return Array.from(this.activeMigrations.values()).filter(
      job => job.status === MigrationStatus.IN_PROGRESS
    );
  }

  /**
   * Get all migrations
   */
  getAllMigrations(): MigrationJob[] {
    return Array.from(this.activeMigrations.values());
  }

  // Helper methods (placeholders for actual implementation)
  
  private async getAllKeysFromShard(shard: ShardNode): Promise<string[]> {
    // Implementation would query the database
    return [];
  }

  private async estimateMigrationSize(shard: ShardNode, keys: string[]): Promise<number> {
    // Implementation would calculate size
    return 0;
  }

  private async copyBatch(source: ShardNode, target: ShardNode, keys: string[]): Promise<void> {
    // Implementation would copy data
  }

  private async getChangesSince(shard: ShardNode, since: Date): Promise<any[]> {
    // Implementation would get CDC changes
    return [];
  }

  private async applyChange(shard: ShardNode, change: any): Promise<void> {
    // Implementation would apply change
  }

  private async getData(shard: ShardNode, key: string): Promise<any> {
    // Implementation would fetch data
    return null;
  }

  private compareData(source: any, target: any): boolean {
    return JSON.stringify(source) === JSON.stringify(target);
  }

  private async enableWriteBlocking(shard: ShardNode): Promise<void> {
    // Implementation would enable blocking
  }

  private async disableWriteBlocking(shard: ShardNode): Promise<void> {
    // Implementation would disable blocking
  }

  private async updateRouting(keys: string[], targetShardId: string): Promise<void> {
    // Implementation would update routing table
  }

  private async deleteData(shard: ShardNode, key: string): Promise<void> {
    // Implementation would delete data
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  private sampleArray<T>(array: T[], size: number): T[] {
    const shuffled = [...array].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, size);
  }

  private emitMigrationEvent(event: string, job: MigrationJob): void {
    this.eventEmitter.emit(`migration.${event}`, job);
  }
}
