import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ShardRouter, CrossShardQueryCoordinator } from './routing/shard-router';
import { ShardMonitor, ShardDashboardService } from './monitoring/shard-monitor';
import { ShardMigrationService } from './migration/shard-migration';

/**
 * Database Sharding Module
 * 
 * Provides horizontal database sharding capabilities including:
 * - Consistent hashing for shard assignment
 * - Shard routing and query coordination
 * - Health monitoring and alerting
 * - Zero-downtime shard migration
 */
@Module({
  imports: [EventEmitterModule.forRoot()],
  providers: [
    ShardRouter,
    CrossShardQueryCoordinator,
    ShardMonitor,
    ShardDashboardService,
    ShardMigrationService,
  ],
  exports: [
    ShardRouter,
    CrossShardQueryCoordinator,
    ShardMonitor,
    ShardDashboardService,
    ShardMigrationService,
  ],
})
export class DatabaseShardingModule {}
