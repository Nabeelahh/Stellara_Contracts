import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { RestoreService } from './restore.service';
import { RestorePointDto } from './dto/backup-config.dto';
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    // In production, check for admin role
    return true;
  }
}

@Controller('admin/restore')
@UseGuards(AdminGuard)
export class RestoreController {
  constructor(private readonly restoreService: RestoreService) {}

  /**
   * Restore from a full backup
   */
  @Post('full')
  @HttpCode(HttpStatus.ACCEPTED)
  async restoreFull(@Body() dto: { backupId: string }) {
    const job = await this.restoreService.restoreFromBackup(dto.backupId);
    return {
      jobId: job.id,
      status: job.status,
      message: 'Restore initiated',
    };
  }

  /**
   * Point-in-time recovery
   */
  @Post('pitr')
  @HttpCode(HttpStatus.ACCEPTED)
  async restorePITR(@Body() dto: RestorePointDto) {
    const targetTime = dto.targetTime ? new Date(dto.targetTime) : new Date();
    const job = await this.restoreService.pointInTimeRecovery(dto.backupId, targetTime);
    return {
      jobId: job.id,
      status: job.status,
      targetTime: targetTime.toISOString(),
      message: 'Point-in-time recovery initiated',
    };
  }

  /**
   * Get restore progress
   */
  @Get('progress/:jobId')
  async getProgress(@Param('jobId') jobId: string) {
    const job = this.restoreService.getRestoreStatus(jobId);
    if (!job) {
      throw new Error(`Restore job ${jobId} not found`);
    }
    return {
      jobId: job.id,
      status: job.status,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      errorMessage: job.errorMessage,
      restoredToTime: job.restoredToTime,
    };
  }

  /**
   * Get all restore jobs
   */
  @Get('jobs')
  async getAllJobs(): Promise<
    Array<{
      id: string;
      backupId: string;
      targetTime?: Date;
      status: string;
      startedAt: Date;
      completedAt?: Date;
      errorMessage?: string;
      restoredToTime?: Date;
    }>
  > {
    return this.restoreService.getAllRestoreJobs();
  }

  /**
   * Validate backup before restore
   */
  @Post('validate')
  @HttpCode(HttpStatus.OK)
  async validateBackup(@Body() dto: { backupId: string }) {
    return this.restoreService.validateBackup(dto.backupId);
  }

  /**
   * Estimate recovery time
   */
  @Post('estimate')
  @HttpCode(HttpStatus.OK)
  async estimateRecovery(@Body() dto: { backupId: string }) {
    return this.restoreService.estimateRecoveryTime(dto.backupId);
  }
}
