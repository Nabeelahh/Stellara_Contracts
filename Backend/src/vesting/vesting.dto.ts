import {
  IsString,
  IsNumber,
  IsEnum,
  IsDateString,
  IsOptional,
  IsArray,
  ValidateNested,
  Min,
  Max,
  IsIn,
} from 'class-validator';
import { Type } from 'class-transformer';

export class VestingMilestoneDto {
  @IsDateString()
  date: string;

  @IsNumber()
  @Min(0)
  @Max(100)
  percentage: number;

  @IsOptional()
  @IsString()
  description?: string;
}

export class CreateVestingScheduleDto {
  @IsString()
  recipientAddress: string;

  @IsNumber()
  @Min(0)
  totalAmount: number;

  @IsEnum(['linear', 'milestone', 'hybrid'])
  scheduleType: 'linear' | 'milestone' | 'hybrid';

  @IsIn([6, 12])
  cliffMonths: 6 | 12;

  @IsDateString()
  startDate: string;

  @IsDateString()
  endDate: string;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => VestingMilestoneDto)
  milestones?: VestingMilestoneDto[];
}

export class TriggerAccelerationDto {
  @IsString()
  vestingId: string;

  @IsEnum(['acquisition', 'ipo', 'termination'])
  reason: 'acquisition' | 'ipo' | 'termination';
}

export class TerminateVestingDto {
  @IsString()
  vestingId: string;

  @IsDateString()
  terminationDate: string;

  @IsString()
  reason: string;
}
