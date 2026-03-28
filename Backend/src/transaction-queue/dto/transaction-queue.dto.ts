import {
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export enum QueuePriorityDto {
  LOW = 'LOW',
  NORMAL = 'NORMAL',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export class EnqueueTransactionDto {
  @IsOptional()
  @IsString()
  idempotencyKey?: string;

  @IsString()
  @IsNotEmpty()
  signerAddress: string;

  @IsString()
  @IsNotEmpty()
  contractAddress: string;

  @IsString()
  @IsNotEmpty()
  functionName: string;

  @IsObject()
  payload: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;

  @IsOptional()
  @IsEnum(QueuePriorityDto)
  priority?: QueuePriorityDto = QueuePriorityDto.NORMAL;

  @IsOptional()
  @IsInt()
  @Min(0)
  nonce?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(10_000_000)
  requestedFeeBid?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(20)
  maxRetries?: number = 5;
}

export class QueueSummaryDto {
  queued: number;
  processing: number;
  submitted: number;
  stuck: number;
  confirmed: number;
  failed: number;
  deadLetter: number;
}

