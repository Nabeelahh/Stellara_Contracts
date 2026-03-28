import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { BackupService } from './backup.service';
import {
  CreateBackupDto,
  VerifyBackupDto,
  BackupResponseDto,
  BackupStatusDto,
} from './dto/backup-config.dto';

// Simple admin guard - in production, use proper RBAC
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
class AdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    // Check for admin role in JWT or session
    // For now, allow all in development
    return true;
  }
}

@Controller('admin/backup')
@UseGuards(AdminGuard)
export class BackupController {
  constructor(private readonly backupService: BackupService) {}

  /**
   * Trigger a manual backup
   */
  @Post('trigger')
  @HttpCode(HttpStatus.ACCEPTED)
  async triggerBackup(@Body() dto: CreateBackupDto): Promise<BackupResponseDto> {
    return this.backupService.createBackup(dto);
  }

  /**
   * Get backup status and history
   */
  @Get('status')
  async getStatus(): Promise<BackupStatusDto> {
    return this.backupService.getBackupStatus();
  }

  /**
   * Get all backups
   */
  @Get('list')
  async getAllBackups(): Promise<BackupResponseDto[]> {
    return this.backupService.getAllBackups();
  }

  /**
   * Get specific backup details
   */
  @Get(':id')
  async getBackup(@Param('id') id: string): Promise<BackupResponseDto> {
    const backup = this.backupService.getBackup(id);
    if (!backup) {
      throw new Error(`Backup ${id} not found`);
    }
    return backup;
  }

  /**
   * Verify a specific backup
   */
  @Post('verify')
  @HttpCode(HttpStatus.ACCEPTED)
  async verifyBackup(@Body() dto: VerifyBackupDto): Promise<{ success: boolean; message: string }> {
    const result = await this.backupService.verifyBackup(dto.backupId);
    return {
      success: result,
      message: result ? 'Backup verified successfully' : 'Backup verification failed',
    };
  }
}
