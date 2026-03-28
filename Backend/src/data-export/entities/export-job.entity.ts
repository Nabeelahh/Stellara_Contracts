import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

export enum ExportStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  EXPIRED = 'expired',
}

export enum ExportFormat {
  JSON = 'json',
  CSV = 'csv',
  XML = 'xml',
}

export enum ExportType {
  USER_DATA = 'user_data',
  TRANSACTIONS = 'transactions',
  CONTRACTS = 'contracts',
  WORKFLOWS = 'workflows',
  AUDIT_LOGS = 'audit_logs',
  ALL_DATA = 'all_data',
}

@Entity('export_jobs')
export class ExportJob {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({
    type: 'enum',
    enum: ExportType,
    name: 'export_type',
  })
  exportType: ExportType;

  @Column({
    type: 'enum',
    enum: ExportFormat,
    name: 'format',
  })
  format: ExportFormat;

  @Column({
    type: 'enum',
    enum: ExportStatus,
    default: ExportStatus.PENDING,
    name: 'status',
  })
  status: ExportStatus;

  @Column({ type: 'jsonb', name: 'filters', nullable: true })
  filters: Record<string, any>;

  @Column({ name: 'file_path', nullable: true })
  filePath: string;

  @Column({ name: 'file_size', type: 'bigint', nullable: true })
  fileSize: bigint;

  @Column({ name: 'download_url', nullable: true })
  downloadUrl: string;

  @Column({ name: 'expires_at', nullable: true })
  expiresAt: Date;

  @Column({ name: 'completed_at', nullable: true })
  completedAt: Date;

  @Column({ type: 'jsonb', name: 'error_data', nullable: true })
  errorData: Record<string, any>;

  @Column({ name: 'progress_percentage', default: 0 })
  progressPercentage: number;

  @Column({ name: 'total_records', nullable: true })
  totalRecords: number;

  @Column({ name: 'processed_records', default: 0 })
  processedRecords: number;

  @Column({ name: 'notification_sent', default: false })
  notificationSent: boolean;

  @Column({ name: 'scheduled_for', nullable: true })
  scheduledFor: Date;

  @Column({ type: 'jsonb', name: 'metadata', nullable: true })
  metadata: Record<string, any>;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
