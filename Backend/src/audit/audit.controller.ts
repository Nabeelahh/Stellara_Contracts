import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus,
  BadRequestException,
} from '@nestjs/common';
import { AuditService } from './audit.service';
import { AuditRetentionService } from './audit-retention.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
  QueryAuditLogsDto,
  GetStatisticsDto,
  CreateRetentionPolicyDto,
  UpdateRetentionPolicyDto,
} from './dto/audit.dto';
import { SkipAudit } from './decorators/audit.decorator';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { AuditAction } from '@prisma/client';

@Controller('audit')
@UseGuards(JwtAuthGuard)
export class AuditController {
  constructor(
    private readonly auditService: AuditService,
    private readonly retentionService: AuditRetentionService,
  ) {}

  /**
   * Query audit logs with filters and pagination
   */
  @Get('logs')
  @SkipAudit() // Don't audit audit log queries to avoid recursion
  async queryLogs(@Query() query: QueryAuditLogsDto) {
    return this.auditService.query({
      ...query,
      startDate: query.startDate ? new Date(query.startDate) : undefined,
      endDate: query.endDate ? new Date(query.endDate) : undefined,
    });
  }

  /**
   * Get a specific audit log entry
   */
  @Get('logs/:id')
  @SkipAudit()
  async getLog(@Param('id') id: string) {
    const log = await this.auditService.getById(id);
    if (!log) {
      throw new BadRequestException(`Audit log not found: ${id}`);
    }
    return log;
  }

  /**
   * Get audit history for a specific entity
   */
  @Get('entity/:entityType/:entityId')
  @SkipAudit()
  async getEntityHistory(
    @Param('entityType') entityType: string,
    @Param('entityId') entityId: string,
    @Query('page') page?: number,
    @Query('limit') limit?: number,
  ) {
    return this.auditService.getEntityHistory(entityType, entityId, {
      page: page ? Number(page) : undefined,
      limit: limit ? Number(limit) : undefined,
    });
  }

  /**
   * Get audit activity for a specific user
   */
  @Get('user/:userId')
  @SkipAudit()
  async getUserActivity(@Param('userId') userId: string, @Query() query: QueryAuditLogsDto) {
    return this.auditService.getUserActivity(userId, {
      ...query,
      startDate: query.startDate ? new Date(query.startDate) : undefined,
      endDate: query.endDate ? new Date(query.endDate) : undefined,
    });
  }

  /**
   * Get my activity (current user)
   */
  @Get('me/activity')
  @SkipAudit()
  async getMyActivity(@CurrentUser() user: { id: string }, @Query() query: QueryAuditLogsDto) {
    return this.auditService.getUserActivity(user.id, {
      ...query,
      startDate: query.startDate ? new Date(query.startDate) : undefined,
      endDate: query.endDate ? new Date(query.endDate) : undefined,
    });
  }

  /**
   * Get audit statistics
   */
  @Get('statistics')
  @SkipAudit()
  async getStatistics(@Query() query: GetStatisticsDto) {
    return this.auditService.getStatistics(
      new Date(query.startDate),
      new Date(query.endDate),
      query.tenantId,
    );
  }

  /**
   * Verify the integrity of an audit log entry
   */
  @Get('logs/:id/verify')
  @SkipAudit()
  async verifyLogIntegrity(@Param('id') id: string) {
    const isValid = await this.auditService.verifyIntegrity(id);
    return {
      id,
      isValid,
      verifiedAt: new Date().toISOString(),
    };
  }

  // ─── Retention Policy Endpoints ────────────────────────────────────────────

  /**
   * Get all retention policies
   */
  @Get('retention/policies')
  @SkipAudit()
  async getRetentionPolicies(@Query('tenantId') tenantId?: string) {
    return this.retentionService.getPolicies(tenantId);
  }

  /**
   * Get a specific retention policy
   */
  @Get('retention/policies/:id')
  @SkipAudit()
  async getRetentionPolicy(@Param('id') id: string) {
    const policy = await this.retentionService.getPolicy(id);
    if (!policy) {
      throw new BadRequestException(`Retention policy not found: ${id}`);
    }
    return policy;
  }

  /**
   * Create a new retention policy
   */
  @Post('retention/policies')
  @HttpCode(HttpStatus.CREATED)
  async createRetentionPolicy(@Body() dto: CreateRetentionPolicyDto) {
    const policyId = await this.retentionService.createPolicy({
      name: dto.name,
      tenantId: dto.tenantId,
      retentionDays: dto.retentionDays,
      entityTypes: dto.entityTypes,
      actions: dto.actions,
      archiveEnabled: dto.archiveEnabled,
      archiveLocation: dto.archiveLocation,
    });

    return { id: policyId, message: 'Retention policy created successfully' };
  }

  /**
   * Update a retention policy
   */
  @Put('retention/policies/:id')
  async updateRetentionPolicy(@Param('id') id: string, @Body() dto: UpdateRetentionPolicyDto) {
    await this.retentionService.updatePolicy(id, {
      name: dto.name,
      retentionDays: dto.retentionDays,
      entityTypes: dto.entityTypes,
      actions: dto.actions,
      archiveEnabled: dto.archiveEnabled,
      archiveLocation: dto.archiveLocation,
      isActive: dto.isActive,
    });

    return { message: 'Retention policy updated successfully' };
  }

  /**
   * Delete a retention policy
   */
  @Delete('retention/policies/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteRetentionPolicy(@Param('id') id: string) {
    await this.retentionService.deletePolicy(id);
  }

  /**
   * Execute a retention policy manually
   */
  @Post('retention/policies/:id/execute')
  async executeRetentionPolicy(@Param('id') id: string) {
    const result = await this.retentionService.executePolicy(id);
    return result;
  }

  /**
   * Get retention statistics
   */
  @Get('retention/stats')
  @SkipAudit()
  async getRetentionStats() {
    return this.retentionService.getRetentionStats();
  }

  /**
   * Manual cleanup endpoint for emergency scenarios
   */
  @Post('retention/cleanup')
  async manualCleanup(
    @Body()
    body: {
      beforeDate: string;
      tenantId?: string;
      entityTypes?: string[];
      actions?: AuditAction[];
      dryRun?: boolean;
    },
  ) {
    const result = await this.retentionService.manualCleanup(new Date(body.beforeDate), {
      tenantId: body.tenantId,
      entityTypes: body.entityTypes,
      actions: body.actions,
      dryRun: body.dryRun,
    });

    return {
      ...result,
      message: result.dryRun
        ? `Dry run: ${result.count} logs would be deleted`
        : `Successfully deleted ${result.count} logs`,
    };
  }
}
