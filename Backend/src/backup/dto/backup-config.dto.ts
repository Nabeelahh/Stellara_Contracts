import { IsString, IsNumber, IsBoolean, IsOptional, IsEnum } from 'class-validator';

export enum BackupType {
  FULL = 'FULL',
  INCREMENTAL = 'INCREMENTAL',
  WAL = 'WAL',
}

export enum BackupStatus {
  PENDING = 'PENDING',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  VERIFYING = 'VERIFYING',
  VERIFIED = 'VERIFIED',
}

export class CreateBackupDto {
  @IsOptional()
  @IsEnum(BackupType)
  type?: BackupType = BackupType.FULL;

  @IsOptional()
  @IsString()
  description?: string;
}

export class BackupResponseDto {
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
  createdAt: Date;
}

export class BackupStatusDto {
  totalBackups: number;
  lastBackupAt?: Date;
  lastBackupStatus?: BackupStatus;
  lastBackupSize?: number;
  nextScheduledBackup?: Date;
  storageUsedBytes: number;
  retentionPolicy: {
    daily: number;
    weekly: number;
    monthly: number;
  };
}

export class RetentionPolicyDto {
  @IsNumber()
  @IsOptional()
  daily?: number = 7;

  @IsNumber()
  @IsOptional()
  weekly?: number = 4;

  @IsNumber()
  @IsOptional()
  monthly?: number = 12;
}

export class VerifyBackupDto {
  @IsString()
  backupId: string;

  @IsOptional()
  @IsBoolean()
  testRestore?: boolean = true;
}

export class RestorePointDto {
  @IsString()
  backupId: string;

  @IsOptional()
  @IsString()
  targetTime?: string;
}
