import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { HealthIndicatorResult, DatabaseHealthDetails } from '../health.types';

@Injectable()
export class DatabaseHealthIndicator {
  private readonly logger = new Logger(DatabaseHealthIndicator.name);

  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
  ) {}

  async isHealthy(): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      // Test database connection
      await this.dataSource.query('SELECT 1');
      
      const latency = Date.now() - startTime;
      
      // Get connection pool info
      const poolInfo = this.getConnectionPoolInfo();
      
      // Check migrations status
      const migrationsOk = await this.checkMigrations();
      
      const details: DatabaseHealthDetails = {
        connection: true,
        latency,
        migrations: migrationsOk,
        pool: poolInfo,
      };

      let status = 'up';
      let message = 'Database is healthy';
      
      // Check for potential issues
      if (latency > 1000) {
        status = 'degraded';
        message = `Database latency is high: ${latency}ms`;
      }
      
      if (!migrationsOk) {
        status = 'degraded';
        message = 'Database migrations are not up to date';
      }

      return {
        name: 'database',
        status,
        message,
        details,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      this.logger.error('Database health check failed', error);
      
      return {
        name: 'database',
        status: 'down',
        message: `Database connection failed: ${error.message}`,
        timestamp: new Date().toISOString(),
      };
    }
  }

  private getConnectionPoolInfo(): { used: number; free: number; pending: number } {
    try {
      // For PostgreSQL
      if (this.dataSource.options.type === 'postgres') {
        // This is a simplified approach - in production you'd query pg_stat_activity
        return {
          used: 0, // Would need to query actual pool stats
          free: 0,
          pending: 0,
        };
      }
      
      // For other databases or when pool info is not available
      return {
        used: 0,
        free: 0,
        pending: 0,
      };
    } catch (error) {
      this.logger.warn('Could not get connection pool info', error);
      return {
        used: 0,
        free: 0,
        pending: 0,
      };
    }
  }

  private async checkMigrations(): Promise<boolean> {
    try {
      // Check if migrations table exists and is up to date
      const queryRunner = this.dataSource.createQueryRunner();
      await queryRunner.connect();
      
      try {
        // Check if migrations table exists
        const hasMigrationsTable = await queryRunner.hasTable('migrations');
        if (!hasMigrationsTable) {
          return true; // No migrations table means no migrations to check
        }
        
        // Get pending migrations count
        const pendingMigrations = await this.dataSource.runMigrations({
          dryRun: true,
          transaction: 'none',
        });
        
        return pendingMigrations.length === 0;
      } finally {
        await queryRunner.release();
      }
    } catch (error) {
      this.logger.warn('Could not check migrations status', error);
      return true; // Don't fail health check on migration check failure
    }
  }
}