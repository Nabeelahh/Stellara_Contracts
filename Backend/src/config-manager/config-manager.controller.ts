import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { RolesGuard } from '../auth/guards/roles.guard';
import { ConfigManagerService } from './services/config-manager.service';
import { FeatureFlagService } from './services/feature-flag.service';
import { ConfigAuditService } from './services/config-audit.service';
import { SetConfigDto, SetFeatureFlagDto } from './dto/config.dto';
import { ConfigScope } from './interfaces/config.interfaces';

@ApiTags('config')
@ApiBearerAuth('JWT-auth')
@Controller('config')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ConfigManagerController {
  constructor(
    private readonly configManager: ConfigManagerService,
    private readonly featureFlags: FeatureFlagService,
    private readonly audit: ConfigAuditService,
  ) {}

  // ─── Config entries ───────────────────────────────────────────────────────

  @Get('resolve')
  @ApiOperation({
    summary: 'Resolve configuration value',
    description: 'Resolves a configuration value considering tenant and user context',
  })
  @ApiQuery({
    name: 'key',
    description: 'Configuration key to resolve',
    example: 'maxUploadSize',
  })
  @ApiQuery({
    name: 'tenantId',
    description: 'Tenant ID for tenant-scoped config',
    required: false,
    example: 'tenant_123',
  })
  @ApiQuery({
    name: 'userId',
    description: 'User ID for user-scoped config',
    required: false,
    example: 'user_456',
  })
  @ApiOkResponse({
    description: 'Configuration value resolved',
    schema: {
      type: 'object',
      properties: {
        key: { type: 'string', example: 'maxUploadSize' },
        value: { type: 'any', example: 10485760 },
      },
    },
  })
  async resolve(
    @Query('key') key: string,
    @Query('tenantId') tenantId?: string,
    @Query('userId') userId?: string,
  ) {
    const value = await this.configManager.get(key, tenantId, userId);
    return { key, value: value ?? null };
  }

  @Post()
  @Roles('ADMIN' as any)
  @ApiOperation({
    summary: 'Set configuration value',
    description: 'Creates or updates a configuration entry. Requires ADMIN role.',
  })
  @ApiBody({ type: SetConfigDto })
  @ApiOkResponse({
    description: 'Configuration set successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
      },
    },
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async set(@Body() dto: SetConfigDto, @Request() req: any) {
    await this.configManager.set(dto, req.user?.id);
    return { success: true };
  }

  @Delete(':key')
  @Roles('ADMIN' as any)
  @ApiOperation({
    summary: 'Delete configuration entry',
    description: 'Deletes a configuration entry. Requires ADMIN role.',
  })
  @ApiParam({
    name: 'key',
    description: 'Configuration key to delete',
    example: 'maxUploadSize',
  })
  @ApiQuery({
    name: 'scope',
    description: 'Configuration scope',
    enum: ConfigScope,
    required: false,
  })
  @ApiQuery({
    name: 'tenantId',
    description: 'Tenant ID for tenant-scoped config',
    required: false,
  })
  @ApiQuery({
    name: 'userId',
    description: 'User ID for user-scoped config',
    required: false,
  })
  @ApiOkResponse({
    description: 'Configuration deleted successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
      },
    },
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async delete(
    @Param('key') key: string,
    @Query('scope') scope: ConfigScope = ConfigScope.GLOBAL,
    @Query('tenantId') tenantId?: string,
    @Query('userId') userId?: string,
    @Request() req?: any,
  ) {
    await this.configManager.delete(key, scope, tenantId, userId, req?.user?.id);
    return { success: true };
  }

  @Get('tenant/:tenantId')
  @Roles('ADMIN' as any)
  @ApiOperation({
    summary: 'List tenant configurations',
    description: 'Lists all configuration entries for a tenant. Requires ADMIN role.',
  })
  @ApiParam({
    name: 'tenantId',
    description: 'Tenant ID',
    example: 'tenant_123',
  })
  @ApiOkResponse({
    description: 'List of tenant configurations',
    type: Array,
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async listForTenant(@Param('tenantId') tenantId: string) {
    return this.configManager.listForTenant(tenantId);
  }

  // ─── Feature flags ────────────────────────────────────────────────────────

  @Get('flags')
  @ApiOperation({
    summary: 'List feature flags',
    description: 'Lists all feature flags, optionally filtered by tenant',
  })
  @ApiQuery({
    name: 'tenantId',
    description: 'Tenant ID to filter flags',
    required: false,
  })
  @ApiOkResponse({
    description: 'List of feature flags',
    type: Array,
  })
  async listFlags(@Query('tenantId') tenantId?: string) {
    return this.featureFlags.listFlags(tenantId);
  }

  @Get('flags/:key')
  @ApiOperation({
    summary: 'Check feature flag status',
    description: 'Checks if a feature flag is enabled for the given context',
  })
  @ApiParam({
    name: 'key',
    description: 'Feature flag key',
    example: 'newDashboard',
  })
  @ApiQuery({
    name: 'tenantId',
    description: 'Tenant ID for tenant-scoped flag',
    required: false,
  })
  @ApiQuery({
    name: 'userId',
    description: 'User ID for user-scoped flag',
    required: false,
  })
  @ApiOkResponse({
    description: 'Feature flag status',
    schema: {
      type: 'object',
      properties: {
        key: { type: 'string', example: 'newDashboard' },
        enabled: { type: 'boolean', example: true },
      },
    },
  })
  async checkFlag(
    @Param('key') key: string,
    @Query('tenantId') tenantId?: string,
    @Query('userId') userId?: string,
  ) {
    const enabled = await this.featureFlags.isEnabled(key, tenantId, userId);
    return { key, enabled };
  }

  @Post('flags')
  @Roles('ADMIN' as any)
  @ApiOperation({
    summary: 'Set feature flag',
    description: 'Creates or updates a feature flag. Requires ADMIN role.',
  })
  @ApiBody({ type: SetFeatureFlagDto })
  @ApiOkResponse({
    description: 'Feature flag set successfully',
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async setFlag(@Body() dto: SetFeatureFlagDto, @Request() req: any) {
    const flag = await this.featureFlags.setFlag(dto, req.user?.id);
    return flag;
  }

  @Delete('flags/:key')
  @Roles('ADMIN' as any)
  @ApiOperation({
    summary: 'Delete feature flag',
    description: 'Deletes a feature flag. Requires ADMIN role.',
  })
  @ApiParam({
    name: 'key',
    description: 'Feature flag key to delete',
    example: 'newDashboard',
  })
  @ApiQuery({
    name: 'tenantId',
    description: 'Tenant ID for tenant-scoped flag',
    required: false,
  })
  @ApiOkResponse({
    description: 'Feature flag deleted successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
      },
    },
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async deleteFlag(
    @Param('key') key: string,
    @Query('tenantId') tenantId?: string,
    @Request() req?: any,
  ) {
    await this.featureFlags.deleteFlag(key, tenantId, req?.user?.id);
    return { success: true };
  }

  // ─── Audit trail ──────────────────────────────────────────────────────────

  @Get('audit/:key')
  @Roles('ADMIN' as any)
  @ApiOperation({
    summary: 'Get configuration audit trail',
    description: 'Retrieves the audit history for a configuration key. Requires ADMIN role.',
  })
  @ApiParam({
    name: 'key',
    description: 'Configuration key to audit',
    example: 'maxUploadSize',
  })
  @ApiQuery({
    name: 'tenantId',
    description: 'Tenant ID for tenant-scoped config',
    required: false,
  })
  @ApiOkResponse({
    description: 'Audit trail for configuration',
    type: Array,
  })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async getAuditTrail(@Param('key') key: string, @Query('tenantId') tenantId?: string) {
    return this.audit.getAuditTrail(key, tenantId);
  }
}
