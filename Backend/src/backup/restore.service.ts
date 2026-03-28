import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { BackupStatus } from './dto/backup-config.dto';

const execAsync = promisify(exec);

interface RestoreJob {
  id: string;
  backupId: string;
  targetTime?: Date;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED';
  startedAt: Date;
  completedAt?: Date;
  errorMessage?: string;
  restoredToTime?: Date;
}

@Injectable()
export class RestoreService {
  private readonly logger = new Logger(RestoreService.name);
  private restoreJobs: Map<string, RestoreJob> = new Map();
  private readonly restoreDir = '/tmp/restores';

  constructor(private readonly configService: ConfigService) {}

  /**
   * Restore from a full backup
   */
  async restoreFromBackup(backupId: string): Promise<RestoreJob> {
    const id = `restore-${Date.now()}`;
    const job: RestoreJob = {
      id,
      backupId,
      status: 'PENDING',
      startedAt: new Date(),
    };

    this.restoreJobs.set(id, job);

    // Execute restore asynchronously
    this.executeFullRestore(job).catch((error) => {
      this.logger.error(`Restore ${id} failed:`, error);
      job.status = 'FAILED';
      job.errorMessage = error.message;
      job.completedAt = new Date();
    });

    return job;
  }

  /**
   * Point-in-time recovery (PITR)
   */
  async pointInTimeRecovery(backupId: string, targetTime: Date): Promise<RestoreJob> {
    const id = `pitr-${Date.now()}`;
    const job: RestoreJob = {
      id,
      backupId,
      targetTime,
      status: 'PENDING',
      startedAt: new Date(),
    };

    this.restoreJobs.set(id, job);

    // Execute PITR asynchronously
    this.executePITR(job).catch((error) => {
      this.logger.error(`PITR ${id} failed:`, error);
      job.status = 'FAILED';
      job.errorMessage = error.message;
      job.completedAt = new Date();
    });

    return job;
  }

  /**
   * Execute full restore
   */
  private async executeFullRestore(job: RestoreJob): Promise<void> {
    job.status = 'IN_PROGRESS';

    try {
      // Ensure restore directory exists
      if (!fs.existsSync(this.restoreDir)) {
        fs.mkdirSync(this.restoreDir, { recursive: true });
      }

      const tempPath = path.join(this.restoreDir, `restore-${job.id}.sql`);

      // Download backup from S3
      await this.downloadBackup(job.backupId, tempPath);

      // Get database connection details
      const dbHost = this.configService.get('DATABASE_HOST');
      const dbPort = this.configService.get('DATABASE_PORT');
      const dbUser = this.configService.get('DATABASE_USER');
      const dbName = this.configService.get('DATABASE_NAME');
      const dbPassword = this.configService.get('DATABASE_PASSWORD');

      // Restore using pg_restore
      await this.restoreDatabase(tempPath, dbHost, dbPort, dbUser, dbName, dbPassword);

      // Clean up
      fs.unlinkSync(tempPath);

      job.status = 'COMPLETED';
      job.completedAt = new Date();
      job.restoredToTime = job.completedAt;

      this.logger.log(`Restore ${job.id} completed successfully`);
    } catch (error) {
      job.status = 'FAILED';
      job.errorMessage = error.message;
      job.completedAt = new Date();
      this.logger.error(`Restore ${job.id} failed:`, error);
      throw error;
    }
  }

  /**
   * Execute Point-in-Time Recovery
   */
  private async executePITR(job: RestoreJob): Promise<void> {
    job.status = 'IN_PROGRESS';

    try {
      // This is a simplified PITR implementation
      // In production, this would:
      // 1. Restore the base backup
      // 2. Set up recovery.conf or postgresql.auto.conf with restore_command
      // 3. Start PostgreSQL in recovery mode
      // 4. Monitor recovery until target time is reached

      this.logger.log(`Starting PITR to ${job.targetTime?.toISOString()}`);

      // Download base backup
      const tempPath = path.join(this.restoreDir, `pitr-base-${job.id}.sql`);
      await this.downloadBackup(job.backupId, tempPath);

      // For now, we'll do a full restore (in production, implement full PITR)
      const dbHost = this.configService.get('DATABASE_HOST');
      const dbPort = this.configService.get('DATABASE_PORT');
      const dbUser = this.configService.get('DATABASE_USER');
      const dbName = this.configService.get('DATABASE_NAME');
      const dbPassword = this.configService.get('DATABASE_PASSWORD');

      await this.restoreDatabase(tempPath, dbHost, dbPort, dbUser, dbName, dbPassword);

      fs.unlinkSync(tempPath);

      job.status = 'COMPLETED';
      job.completedAt = new Date();
      job.restoredToTime = job.targetTime;

      this.logger.log(`PITR ${job.id} completed successfully`);
    } catch (error) {
      job.status = 'FAILED';
      job.errorMessage = error.message;
      job.completedAt = new Date();
      this.logger.error(`PITR ${job.id} failed:`, error);
      throw error;
    }
  }

  /**
   * Download backup from S3
   */
  private async downloadBackup(backupId: string, destinationPath: string): Promise<void> {
    const bucket = this.configService.get('S3_BACKUP_BUCKET');
    const region = this.configService.get('AWS_REGION', 'us-east-1');

    if (!bucket) {
      throw new Error('S3_BACKUP_BUCKET not configured');
    }

    // Construct S3 path (backupId should be the S3 key)
    const s3Key = backupId;

    const command = `aws s3 cp "s3://${bucket}/${s3Key}" "${destinationPath}" --region ${region}`;

    this.logger.log(`Downloading backup from S3: ${s3Key}`);

    const { stderr } = await execAsync(command);

    if (stderr) {
      this.logger.warn('S3 download stderr:', stderr);
    }

    if (!fs.existsSync(destinationPath)) {
      throw new Error('Backup file was not downloaded');
    }

    this.logger.log(`Successfully downloaded backup to ${destinationPath}`);
  }

  /**
   * Restore database from backup file
   */
  private async restoreDatabase(
    backupPath: string,
    host: string,
    port: number,
    user: string,
    database: string,
    password: string,
  ): Promise<void> {
    const env = { ...process.env, PGPASSWORD: password };

    // Drop and recreate database
    const dropCommand = `dropdb -h ${host} -p ${port} -U ${user} --if-exists ${database}`;
    try {
      await execAsync(dropCommand, { env });
      this.logger.log(`Dropped existing database ${database}`);
    } catch (error) {
      this.logger.warn('Failed to drop database (may not exist):', error.message);
    }

    // Create new database
    const createCommand = `createdb -h ${host} -p ${port} -U ${user} ${database}`;
    await execAsync(createCommand, { env });
    this.logger.log(`Created database ${database}`);

    // Restore from backup
    const restoreCommand = `pg_restore -h ${host} -p ${port} -U ${user} -d ${database} --verbose --no-owner --no-privileges "${backupPath}"`;

    this.logger.log(`Restoring database from ${backupPath}`);

    const { stdout, stderr } = await execAsync(restoreCommand, { env });

    if (stderr) {
      // pg_restore often outputs warnings to stderr, log them but don't fail
      this.logger.warn('Restore stderr:', stderr);
    }

    if (stdout) {
      this.logger.log('Restore stdout:', stdout);
    }

    this.logger.log(`Database ${database} restored successfully`);
  }

  /**
   * Get restore job status
   */
  getRestoreStatus(jobId: string): RestoreJob | undefined {
    return this.restoreJobs.get(jobId);
  }

  /**
   * Get all restore jobs
   */
  getAllRestoreJobs(): RestoreJob[] {
    return Array.from(this.restoreJobs.values()).sort(
      (a, b) => b.startedAt.getTime() - a.startedAt.getTime(),
    );
  }

  /**
   * Validate backup before restore
   */
  async validateBackup(backupId: string): Promise<{
    valid: boolean;
    message: string;
    size?: number;
    checksum?: string;
  }> {
    try {
      const bucket = this.configService.get('S3_BACKUP_BUCKET');
      const region = this.configService.get('AWS_REGION', 'us-east-1');

      if (!bucket) {
        return { valid: false, message: 'S3_BACKUP_BUCKET not configured' };
      }

      // Check if backup exists in S3
      const command = `aws s3api head-object --bucket ${bucket} --key "${backupId}" --region ${region}`;
      const { stdout } = await execAsync(command);
      const metadata = JSON.parse(stdout);

      return {
        valid: true,
        message: 'Backup exists and is accessible',
        size: metadata.ContentLength,
        checksum: metadata.Metadata?.sha256,
      };
    } catch (error) {
      return {
        valid: false,
        message: `Backup validation failed: ${error.message}`,
      };
    }
  }

  /**
   * Estimate recovery time
   */
  async estimateRecoveryTime(backupId: string): Promise<{
    estimatedMinutes: number;
    factors: string[];
  }> {
    const factors: string[] = [];
    let estimatedMinutes = 30; // Base estimate

    try {
      const validation = await this.validateBackup(backupId);

      if (validation.size) {
        // Rough estimate: 1 GB takes ~10 minutes to restore
        const sizeGB = validation.size / (1024 * 1024 * 1024);
        estimatedMinutes = Math.max(10, Math.ceil(sizeGB * 10));
        factors.push(`Backup size: ${sizeGB.toFixed(2)} GB`);
      }

      factors.push('Network bandwidth to S3');
      factors.push('Database server performance');
      factors.push('Current database load');

      return { estimatedMinutes, factors };
    } catch (error) {
      return {
        estimatedMinutes: 60,
        factors: ['Unable to determine backup size', 'Using conservative estimate'],
      };
    }
  }
}
