import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MigrationExecutor } from './migration-executor';
import { MigrationTestingService } from './migration-testing.service';
import { MigrationManagerService } from './migration-manager.service';
import {
  MigrationValidator,
  MigrationBackup,
  MigrationRollback,
  MigrationMetrics,
} from './migration-strategy';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'sqlite',
      database: process.env.DATABASE_PATH || './stellar-events.db',
      entities: [__dirname + '/../**/*.entity{.ts,.js}'],
      synchronize: process.env.NODE_ENV !== 'production', // Auto-create tables in dev
      logging: process.env.NODE_ENV !== 'production',
    }),
  ],
  providers: [
    MigrationExecutor,
    MigrationTestingService,
    MigrationManagerService,
    MigrationValidator,
    MigrationBackup,
    MigrationRollback,
    MigrationMetrics,
  ],
  exports: [
    TypeOrmModule,
    MigrationExecutor,
    MigrationTestingService,
    MigrationManagerService,
    MigrationValidator,
    MigrationBackup,
    MigrationRollback,
    MigrationMetrics,
  ],
})
export class DatabaseModule {}