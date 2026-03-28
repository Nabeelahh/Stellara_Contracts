import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron, CronExpression } from '@nestjs/schedule';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  BackupType,
  BackupStatus,
  CreateBackupDto,
  BackupResponseDto,
  BackupStatusDto,
} from './dto/backup-config.dto';

const execAsync = promisify(exec);

interface BackupJob {
  id: string;
  type: BackupType;
  status: BackupStatus;
  startedAt: Date;
  completedAt?: Date;
  sizeBytes?: number;
  checksum?: string;
  s3Location?: string;
  errorMessage?: string;
  description?: string;
  localPath?: string;
}

@Injectable()
export class BackupService implements OnModuleInit {
  private readonly logger = new Logger(BackupService.name);
  private backupJobs: Map<string, BackupJob> = new Map();
  private readonly backupDir = '/tmp/backups';

  constructor(private readonly configService: ConfigService) {}

  onModuleInit() {
    this.ensureBackupDirectory();
    this.logger.log('Backup service initialized');
  }

  private ensureBackupDirectory() {
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  /**
   * Trigger a manual backup
   */
  async createBackup(dto: CreateBackupDto): Promise<BackupResponseDto> {
    const id = crypto.randomUUID();
    const job: BackupJob = {
      id,
      type: dto.type || BackupType.FULL,
      status: BackupStatus.PENDING,
      startedAt: new Date(),
      description: dto.description,
    };

    this.backupJobs.set(id, job);

    // Start backup asynchronously
    this.executeBackup(job).catch((error) => {
      this.logger.error(`Backup ${id} failed:`, error);
      job.status = BackupStatus.FAILED;
      job.errorMessage = error.message;
      job.completedAt = new Date();
    });

    return this.toResponseDto(job);
  }

  /**
   * Scheduled daily backup at 2 AM
   */
  @Cron('0 2 * * *', {
    name: 'daily-backup',
    timeZone: 'UTC',
  })
  async scheduledDailyBackup() {
    this.logger.log('Starting scheduled daily backup');
    try {
      await this.createBackup({
        type: BackupType.FULL,
        description: 'Automated daily backup',
      });
    } catch (error) {
      this.logger.error('Scheduled backup failed:', error);
    }
  }

  /**
   * Execute the backup process
   */
  private async executeBackup(job: BackupJob): Promise<void> {
    job.status = BackupStatus.IN_PROGRESS;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `backup-${job.type}-${timestamp}.tar.gz`;
    const localPath = path.join(this.backupDir, backupFileName);
    job.localPath = localPath;

    try {
      // Get database connection details
      const dbHost = this.configService.get('DATABASE_HOST');
      const dbPort = this.configService.get('DATABASE_PORT');
      const dbUser = this.configService.get('DATABASE_USER');
      const dbName = this.configService.get('DATABASE_NAME');
      const dbPassword = this.configService.get('DATABASE_PASSWORD');

      // Create backup using pg_basebackup for full backups
      if (job.type === BackupType.FULL) {
        await this.createFullBackup(localPath, dbHost, dbPort, dbUser, dbName, dbPassword);
      } else {
        throw new Error(`Backup type ${job.type} not yet implemented`);
      }

      // Calculate checksum
      job.checksum = await this.calculateChecksum(localPath);
      job.sizeBytes = fs.statSync(localPath).size;

      // Upload to S3
      job.status = BackupStatus.COMPLETED;
      const s3Key = await this.uploadToS3(localPath, backupFileName);
      job.s3Location = s3Key;

      // Clean up local file
      fs.unlinkSync(localPath);

      job.completedAt = new Date();
      this.logger.log(`Backup ${job.id} completed successfully`);

      // Trigger verification if enabled
      if (this.configService.get('BACKUP_VERIFY_AFTER_UPLOAD', true)) {
        this.verifyBackup(job.id).catch((err) => {
          this.logger.error(`Verification failed for backup ${job.id}:`, err);
        });
      }
    } catch (error) {
      job.status = BackupStatus.FAILED;
      job.errorMessage = error.message;
      job.completedAt = new Date();
      this.logger.error(`Backup ${job.id} failed:`, error);
      throw error;
    }
  }

  /**
   * Create a full backup using pg_dump
   */
  private async createFullBackup(
    outputPath: string,
    host: string,
    port: number,
    user: string,
    database: string,
    password: string,
  ): Promise<void> {
    const env = { ...process.env, PGPASSWORD: password };

    // Use pg_dump for SQL backup (more portable)
    const command = `pg_dump -h ${host} -p ${port} -U ${user} -d ${database} -F c -f ${outputPath}`;

    this.logger.log(`Executing backup command: ${command.replace(password, '***')}`);

    const { stdout, stderr } = await execAsync(command, { env });

    if (stderr) {
      this.logger.warn('Backup stderr:', stderr);
    }

    if (stdout) {
      this.logger.log('Backup stdout:', stdout);
    }

    // Verify backup file was created
    if (!fs.existsSync(outputPath)) {
      throw new Error('Backup file was not created');
    }
  }

  /**
   * Calculate SHA-256 checksum of a file
   */
  private async calculateChecksum(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);

      stream.on('error', reject);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
    });
  }

  /**
   * Upload backup to S3
   */
  private async uploadToS3(localPath: string, fileName: string): Promise<string> {
    const bucket = this.configService.get('S3_BACKUP_BUCKET');
    const prefix = this.configService.get('S3_BACKUP_PREFIX', 'postgresql');
    const region = this.configService.get('AWS_REGION', 'us-east-1');

    if (!bucket) {
      throw new Error('S3_BACKUP_BUCKET not configured');
    }

    const datePrefix = new Date().toISOString().slice(0, 10).replace(/-/g, '/');
    const s3Key = `${prefix}/${datePrefix}/${fileName}`;

    const command = `aws s3 cp "${localPath}" "s3://${bucket}/${s3Key}" --region ${region}`;

    this.logger.log(`Uploading to S3: ${s3Key}`);

    const { stderr } = await execAsync(command);

    if (stderr) {
      this.logger.warn('S3 upload stderr:', stderr);
    }

    this.logger.log(`Successfully uploaded to s3://${bucket}/${s3Key}`);
    return s3Key;
  }

  /**
   * Verify a backup by downloading and checking checksum
   */
  async verifyBackup(backupId: string): Promise<boolean> {
    const job = this.backupJobs.get(backupId);
    if (!job) {
      throw new Error(`Backup ${backupId} not found`);
    }

    if (job.status !== BackupStatus.COMPLETED) {
      throw new Error(`Backup ${backupId} is not in COMPLETED status`);
    }

    job.status = BackupStatus.VERIFYING;

    try {
      const bucket = this.configService.get('S3_BACKUP_BUCKET');
      const region = this.configService.get('AWS_REGION', 'us-east-1');
      const tempPath = path.join(this.backupDir, `verify-${backupId}.tar.gz`);

      // Download from S3
      const command = `aws s3 cp "s3://${bucket}/${job.s3Location}" "${tempPath}" --region ${region}`;
      await execAsync(command);

      // Verify checksum
      const downloadedChecksum = await this.calculateChecksum(tempPath);

      // Clean up
      fs.unlinkSync(tempPath);

      if (downloadedChecksum !== job.checksum) {
        throw new Error(`Checksum mismatch: expected ${job.checksum}, got ${downloadedChecksum}`);
      }

      job.status = BackupStatus.VERIFIED;
      this.logger.log(`Backup ${backupId} verified successfully`);
      return true;
    } catch (error) {
      job.status = BackupStatus.COMPLETED; // Revert to completed, verification failed
      this.logger.error(`Backup ${backupId} verification failed:`, error);
      throw error;
    }
  }

  /**
   * Get backup status and history
   */
  getBackupStatus(): BackupStatusDto {
    const jobs = Array.from(this.backupJobs.values());
    const completedJobs = jobs.filter(
      (j) => j.status === BackupStatus.COMPLETED || j.status === BackupStatus.VERIFIED,
    );

    const lastBackup = completedJobs.sort(
      (a, b) => b.completedAt!.getTime() - a.completedAt!.getTime(),
    )[0];

    // Calculate next scheduled backup (2 AM UTC)
    const now = new Date();
    const nextBackup = new Date(now);
    nextBackup.setUTCHours(2, 0, 0, 0);
    if (nextBackup <= now) {
      nextBackup.setUTCDate(nextBackup.getUTCDate() + 1);
    }

    return {
      totalBackups: jobs.length,
      lastBackupAt: lastBackup?.completedAt,
      lastBackupStatus: lastBackup?.status,
      lastBackupSize: lastBackup?.sizeBytes,
      nextScheduledBackup: nextBackup,
      storageUsedBytes: completedJobs.reduce((sum, j) => sum + (j.sizeBytes || 0), 0),
      retentionPolicy: {
        daily: this.configService.get('BACKUP_RETENTION_DAYS', 7),
        weekly: this.configService.get('BACKUP_RETENTION_WEEKS', 4),
        monthly: this.configService.get('BACKUP_RETENTION_MONTHS', 12),
      },
    };
  }

  /**
   * Get all backups
   */
  getAllBackups(): BackupResponseDto[] {
    return Array.from(this.backupJobs.values())
      .sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime())
      .map((job) => this.toResponseDto(job));
  }

  /**
   * Get a specific backup
   */
  getBackup(id: string): BackupResponseDto | undefined {
    const job = this.backupJobs.get(id);
    return job ? this.toResponseDto(job) : undefined;
  }

  /**
   * Clean up old backups based on retention policy
   */
  @Cron(CronExpression.EVERY_DAY_AT_3AM, {
    name: 'cleanup-old-backups',
    timeZone: 'UTC',
  })
  async cleanupOldBackups() {
    this.logger.log('Starting backup retention cleanup');

    const dailyRetention = this.configService.get('BACKUP_RETENTION_DAYS', 7);
    const bucket = this.configService.get('S3_BACKUP_BUCKET');
    const region = this.configService.get('AWS_REGION', 'us-east-1');

    if (!bucket) {
      this.logger.warn('S3_BACKUP_BUCKET not configured, skipping cleanup');
      return;
    }

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - dailyRetention);

    try {
      // List objects in S3
      const command = `aws s3api list-objects-v2 --bucket ${bucket} --prefix postgresql/ --query "Contents[?LastModified<='${cutoffDate.toISOString()}'].Key" --output text --region ${region}`;
      const { stdout } = await execAsync(command);

      const keysToDelete = stdout.trim().split('\n').filter(Boolean);

      if (keysToDelete.length === 0) {
        this.logger.log('No old backups to clean up');
        return;
      }

      this.logger.log(`Found ${keysToDelete.length} old backups to delete`);

      // Delete old objects
      for (const key of keysToDelete) {
        try {
          await execAsync(`aws s3 rm "s3://${bucket}/${key}" --region ${region}`);
          this.logger.log(`Deleted old backup: ${key}`);
        } catch (error) {
          this.logger.error(`Failed to delete ${key}:`, error);
        }
      }
    } catch (error) {
      this.logger.error('Backup cleanup failed:', error);
    }
  }

  /**
   * Convert job to response DTO
   */
  private toResponseDto(job: BackupJob): BackupResponseDto {
    return {
      id: job.id,
      type: job.type,
      status: job.status,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      sizeBytes: job.sizeBytes,
      checksum: job.checksum,
      s3Location: job.s3Location,
      errorMessage: job.errorMessage,
      description: job.description,
      createdAt: job.startedAt,
    };
  }
}
