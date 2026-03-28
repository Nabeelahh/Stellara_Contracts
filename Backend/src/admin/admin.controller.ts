import {
  Controller,
  Get,
  Post,
  Put,
  Query,
  Body,
  Param,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  ParseUUIDPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Roles } from '../decorators/roles.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { AdminService } from './admin.service';
import {
  UserFilterDto,
  UserManagementDto,
  ImpersonationDto,
  AuditLogQueryDto,
  ManualOverrideDto,
  SystemMetricsDto,
  TenantUsageDto,
  HealthCheckDto,
} from './dto/admin.dto';
import { User } from '../auth/entities/user.entity';
import { AuditLog } from '../audit/audit.entity';

@ApiTags('Admin')
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
@Roles('admin')
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Get('users')
  @ApiOperation({ summary: 'Get users with filtering and pagination' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  async getUsers(
    @Query() filter: UserFilterDto,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 20,
  ): Promise<{ users: User[]; total: number }> {
    return await this.adminService.getUsers(filter, page, limit);
  }

  @Put('users/:userId')
  @ApiOperation({ summary: 'Update user information' })
  @ApiResponse({ status: 200, description: 'User updated successfully' })
  async updateUser(
    @Param('userId', ParseUUIDPipe) userId: string,
    @Body() updateData: UserManagementDto,
    @Request() req: any,
  ): Promise<User> {
    return await this.adminService.updateUser(userId, updateData, req.user.userId);
  }

  @Post('users/:userId/suspend')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Suspend a user' })
  @ApiResponse({ status: 200, description: 'User suspended successfully' })
  async suspendUser(
    @Param('userId', ParseUUIDPipe) userId: string,
    @Body() body: { reason: string },
    @Request() req: any,
  ): Promise<User> {
    return await this.adminService.suspendUser(userId, body.reason, req.user.userId);
  }

  @Post('users/:userId/activate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Activate a user' })
  @ApiResponse({ status: 200, description: 'User activated successfully' })
  async activateUser(
    @Param('userId', ParseUUIDPipe) userId: string,
    @Request() req: any,
  ): Promise<User> {
    return await this.adminService.activateUser(userId, req.user.userId);
  }

  @Post('impersonate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Impersonate a user' })
  @ApiResponse({ status: 200, description: 'Impersonation token generated' })
  async impersonateUser(
    @Body() impersonationDto: ImpersonationDto,
    @Request() req: any,
  ): Promise<{ token: string; expiresAt: Date }> {
    return await this.adminService.impersonateUser(impersonationDto, req.user.userId);
  }

  @Get('metrics')
  @ApiOperation({ summary: 'Get system-wide metrics' })
  @ApiResponse({ status: 200, description: 'System metrics retrieved', type: SystemMetricsDto })
  async getSystemMetrics(): Promise<SystemMetricsDto> {
    return await this.adminService.getSystemMetrics();
  }

  @Get('tenant-usage')
  @ApiOperation({ summary: 'Get tenant usage statistics' })
  @ApiResponse({ status: 200, description: 'Tenant usage retrieved', type: [TenantUsageDto] })
  async getTenantUsage(): Promise<TenantUsageDto[]> {
    return await this.adminService.getTenantUsage();
  }

  @Get('health')
  @ApiOperation({ summary: 'Get system health status' })
  @ApiResponse({ status: 200, description: 'Health check completed', type: HealthCheckDto })
  async getHealthCheck(): Promise<HealthCheckDto> {
    return await this.adminService.getHealthCheck();
  }

  @Get('audit-logs')
  @ApiOperation({ summary: 'Get audit logs with filtering' })
  @ApiResponse({ status: 200, description: 'Audit logs retrieved' })
  async getAuditLogs(
    @Query() query: AuditLogQueryDto,
  ): Promise<{ logs: AuditLog[]; total: number }> {
    return await this.adminService.getAuditLogs(query);
  }

  @Post('manual-override')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Perform manual override on entities' })
  @ApiResponse({ status: 200, description: 'Override performed successfully' })
  async performManualOverride(
    @Body() overrideDto: ManualOverrideDto,
    @Request() req: any,
  ): Promise<any> {
    return await this.adminService.performManualOverride(overrideDto, req.user.userId);
  }
}
