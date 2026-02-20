import { Controller, Get, Post, Param, Body, Query, UseGuards, Req } from '@nestjs/common';
import { DataExportService } from '../services/data-export.service';
import { DataDeletionService } from '../services/data-deletion.service';
import { ConsentManagementService } from '../services/consent-management.service';
import { DataRetentionService } from '../services/data-retention.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../guards/roles.guard';
import { Roles } from '../../decorators/roles.decorator';
import { Role } from '../../auth/roles.enum';
import { ConsentType } from '../entities/consent.entity';

export class ExportRequestDto {
  format: 'json' | 'csv' = 'json';
}

export class DeletionRequestDto {
  reason?: string;
}

export class ConsentUpdateDto {
  consentType: ConsentType;
  granted: boolean;
  version?: string;
  consentText?: string;
}

@Controller('gdpr')
@UseGuards(JwtAuthGuard)
export class GdprController {
  constructor(
    private readonly dataExportService: DataExportService,
    private readonly dataDeletionService: DataDeletionService,
    private readonly consentManagementService: ConsentManagementService,
    private readonly dataRetentionService: DataRetentionService,
  ) {}

  // User-facing endpoints

  @Get('export')
  async exportData(
    @Req() req: any,
    @Query() query: ExportRequestDto,
  ) {
    const userId = req.user.id;
    
    if (query.format === 'csv') {
      return {
        data: await this.dataExportService.exportUserDataAsCsv(userId),
        format: 'csv',
      };
    } else {
      return {
        data: await this.dataExportService.exportUserDataAsJson(userId),
        format: 'json',
      };
    }
  }

  @Post('delete-request')
  async requestDeletion(
    @Req() req: any,
    @Body() body: DeletionRequestDto,
  ) {
    const userId = req.user.id;
    const deletionRequest = await this.dataDeletionService.requestDeletion(userId, body.reason);
    
    return {
      success: true,
      message: 'Deletion request submitted successfully',
      requestId: deletionRequest.id,
      retentionUntil: deletionRequest.retentionUntil,
    };
  }

  @Get('consent')
  async getUserConsents(@Req() req: any) {
    const userId = req.user.id;
    const consents = await this.consentManagementService.getAllConsents(userId);
    
    return {
      consents,
    };
  }

  @Post('consent')
  async updateConsent(
    @Req() req: any,
    @Body() body: ConsentUpdateDto,
  ) {
    const userId = req.user.id;
    
    if (body.granted) {
      const consent = await this.consentManagementService.grantConsent(userId, {
        consentType: body.consentType,
        granted: true,
        version: body.version,
        consentText: body.consentText,
      });
      
      return {
        success: true,
        message: 'Consent granted successfully',
        consent,
      };
    } else {
      const consent = await this.consentManagementService.withdrawConsent(userId, body.consentType);
      
      return {
        success: true,
        message: 'Consent withdrawn successfully',
        consent,
      };
    }
  }

  @Get('deletion-status')
  async getDeletionStatus(@Req() req: any) {
    const userId = req.user.id;
    const status = await this.dataDeletionService.getDeletionStatus(userId);
    
    return {
      isActive: status.isActive,
      deletionRequested: status.deletionRequested,
      retentionUntil: status.retentionUntil,
    };
  }
}

@Controller('admin/gdpr')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(Role.ADMIN)
export class AdminGdprController {
  constructor(
    private readonly dataDeletionService: DataDeletionService,
    private readonly consentManagementService: ConsentManagementService,
    private readonly dataRetentionService: DataRetentionService,
  ) {}

  @Get('requests')
  async getPendingRequests() {
    // In a real implementation, this would query a deletion requests table
    return {
      pendingRequests: [],
      total: 0,
    };
  }

  @Post('process-deletion/:requestId')
  async processDeletion(
    @Param('requestId') requestId: string,
    @Req() req: any,
  ) {
    const adminId = req.user.id;
    const stats = await this.dataDeletionService.processDeletion(requestId, adminId);
    
    return {
      success: true,
      message: 'Deletion processed successfully',
      stats,
    };
  }

  @Post('cancel-deletion/:userId')
  async cancelDeletion(@Param('userId') userId: string) {
    await this.dataDeletionService.cancelDeletion(userId);
    
    return {
      success: true,
      message: 'Deletion cancelled successfully',
    };
  }

  @Get('consent-reports')
  async getConsentReports() {
    const analytics = await this.consentManagementService.getConsentAnalytics();
    
    return {
      analytics,
    };
  }

  @Post('update-consent-version')
  async updateConsentVersion(
    @Body() body: { consentType: ConsentType; newVersion: string; consentText: string },
  ) {
    const affectedCount = await this.consentManagementService.updateConsentVersion(
      body.consentType,
      body.newVersion,
      body.consentText,
    );
    
    return {
      success: true,
      message: `Updated ${affectedCount} consents to version ${body.newVersion}`,
      affectedCount,
    };
  }

  @Post('retention-cleanup')
  async executeRetentionCleanup() {
    const results = await this.dataRetentionService.executeRetentionCleanup();
    
    return {
      success: true,
      message: 'Retention cleanup executed successfully',
      results,
    };
  }

  @Get('retention-policies')
  async getRetentionPolicies() {
    const policies = await this.dataRetentionService.getRetentionPolicies();
    
    return {
      policies,
    };
  }

  @Get('retention-statistics')
  async getRetentionStatistics() {
    const statistics = await this.dataRetentionService.getRetentionStatistics();
    
    return {
      statistics,
    };
  }

  @Post('expire-consents')
  async expireOutdatedConsents() {
    const expiredCount = await this.consentManagementService.expireOutdatedConsents();
    
    return {
      success: true,
      message: `Expired ${expiredCount} outdated consents`,
      expiredCount,
    };
  }
}