// src/secrets-management/secrets-management.controller.ts
import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { SecretsManagementService } from './secrets-management.service';
import { SecretRotationService } from './secret-rotation.service';
import { SecretAccessLoggerService } from './secret-access-logger.service';

@ApiTags('Secrets Management')
@Controller('secrets-management')
export class SecretsManagementController {
  constructor(
    private readonly secretsService: SecretsManagementService,
    private readonly rotationService: SecretRotationService,
    private readonly accessLogger: SecretAccessLoggerService,
  ) {}

  @Get('secrets')
  @ApiOperation({ summary: 'Get all secrets metadata' })
  @ApiResponse({ status: 200, description: 'List of all secrets metadata' })
  async getSecretsMetadata() {
    return this.secretsService.getSecretsMetadata();
  }

  @Get('secrets/:name')
  @ApiOperation({ summary: 'Get a specific secret value' })
  @ApiParam({ name: 'name', description: 'Secret name' })
  @ApiResponse({ status: 200, description: 'Secret value' })
  @ApiResponse({ status: 404, description: 'Secret not found' })
  async getSecret(@Param('name') secretName: string) {
    const secret = await this.secretsService.getSecret(secretName, 'api-controller');
    if (!secret) {
      return { error: 'Secret not found or access denied' };
    }
    return secret;
  }

  @Post('secrets')
  @ApiOperation({ summary: 'Create or update a secret' })
  @ApiResponse({ status: 201, description: 'Secret created/updated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid request' })
  async createSecret(
    @Body() body: {
      secretName: string;
      secretData: any;
      secretType: string;
      description?: string;
      rotationSchedule?: string;
    },
  ) {
    const success = await this.secretsService.putSecret(
      body.secretName,
      body.secretData,
      body.secretType,
      body.description,
      body.rotationSchedule,
      'api-controller',
    );

    if (success) {
      return { message: 'Secret created/updated successfully' };
    } else {
      return { error: 'Failed to create/update secret' };
    }
  }

  @Post('secrets/:name/rotate')
  @ApiOperation({ summary: 'Rotate a specific secret' })
  @ApiParam({ name: 'name', description: 'Secret name' })
  @ApiResponse({ status: 200, description: 'Secret rotated successfully' })
  async rotateSecret(
    @Param('name') secretName: string,
    @Body() body?: { reason?: string },
  ) {
    const result = await this.rotationService.rotateSecretManually(
      secretName,
      'api-controller',
      body?.reason,
    );
    return result;
  }

  @Post('secrets/rotate/type/:type')
  @ApiOperation({ summary: 'Rotate all secrets of a specific type' })
  @ApiParam({ name: 'type', description: 'Secret type (database, jwt, api_key, etc.)' })
  @ApiResponse({ status: 200, description: 'Bulk rotation results' })
  async rotateSecretsByType(
    @Param('type') secretType: string,
    @Body() body?: { reason?: string },
  ) {
    const result = await this.rotationService.rotateSecretsByType(
      secretType,
      'api-controller',
      body?.reason,
    );
    return result;
  }

  @Post('secrets/rotate/emergency')
  @ApiOperation({ summary: 'Emergency rotate all secrets' })
  @ApiResponse({ status: 200, description: 'Emergency rotation results' })
  async emergencyRotateAllSecrets(@Body() body: { reason: string }) {
    const result = await this.rotationService.emergencyRotateAllSecrets(
      'api-controller',
      body.reason,
    );
    return result;
  }

  @Post('secrets/:name/revoke')
  @ApiOperation({ summary: 'Emergency revoke a secret' })
  @ApiParam({ name: 'name', description: 'Secret name' })
  @ApiResponse({ status: 200, description: 'Secret revoked successfully' })
  async emergencyRevokeSecret(
    @Param('name') secretName: string,
    @Body() body: { reason: string },
  ) {
    const success = await this.secretsService.emergencyRevokeSecret(
      secretName,
      'api-controller',
      body.reason,
    );

    if (success) {
      return { message: 'Secret emergency revoked successfully' };
    } else {
      return { error: 'Failed to revoke secret' };
    }
  }

  @Put('secrets/:name/schedule')
  @ApiOperation({ summary: 'Update rotation schedule for a secret' })
  @ApiParam({ name: 'name', description: 'Secret name' })
  @ApiResponse({ status: 200, description: 'Rotation schedule updated' })
  async updateRotationSchedule(
    @Param('name') secretName: string,
    @Body() body: { schedule: string },
  ) {
    const result = await this.rotationService.updateRotationSchedule(
      secretName,
      body.schedule,
      'api-controller',
    );
    return result;
  }

  @Get('rotation/status')
  @ApiOperation({ summary: 'Get rotation status for all secrets' })
  @ApiResponse({ status: 200, description: 'Rotation status for all secrets' })
  async getRotationStatus() {
    return this.rotationService.getRotationStatus();
  }

  @Post('rotation/force/:name')
  @ApiOperation({ summary: 'Force immediate rotation of a secret' })
  @ApiParam({ name: 'name', description: 'Secret name' })
  @ApiResponse({ status: 200, description: 'Force rotation result' })
  async forceRotateSecret(
    @Param('name') secretName: string,
    @Body() body: { reason: string },
  ) {
    const result = await this.rotationService.forceRotateSecret(
      secretName,
      'api-controller',
      body.reason,
    );
    return result;
  }

  @Get('access/logs')
  @ApiOperation({ summary: 'Get access logs' })
  @ApiQuery({ name: 'secret', required: false, description: 'Filter by secret name' })
  @ApiQuery({ name: 'limit', required: false, description: 'Limit results' })
  @ApiQuery({ name: 'offset', required: false, description: 'Offset for pagination' })
  @ApiResponse({ status: 200, description: 'Access logs' })
  async getAccessLogs(
    @Query('secret') secretName?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ) {
    if (secretName) {
      return this.accessLogger.getAccessLogs(
        secretName,
        parseInt(limit || '100'),
        parseInt(offset || '0'),
      );
    }

    // Get all access logs (this would be paginated in production)
    const secrets = await this.secretsService.getSecretsMetadata();
    const allLogs = [];

    for (const secret of secrets) {
      const logs = await this.accessLogger.getAccessLogs(secret.secretName, 10, 0);
      allLogs.push(...logs);
    }

    // Sort by access time and limit
    return allLogs
      .sort((a, b) => new Date(b.accessedAt).getTime() - new Date(a.accessedAt).getTime())
      .slice(0, parseInt(limit || '100'));
  }

  @Get('alerts')
  @ApiOperation({ summary: 'Get security alerts' })
  @ApiQuery({ name: 'resolved', required: false, description: 'Filter by resolved status' })
  @ApiQuery({ name: 'limit', required: false, description: 'Limit results' })
  @ApiResponse({ status: 200, description: 'Security alerts' })
  async getSecurityAlerts(
    @Query('resolved') resolved?: string,
    @Query('limit') limit?: string,
  ) {
    return this.accessLogger.getSecurityAlerts(
      resolved === 'true',
      parseInt(limit || '50'),
    );
  }

  @Post('alerts/:id/resolve')
  @ApiOperation({ summary: 'Resolve a security alert' })
  @ApiParam({ name: 'id', description: 'Alert ID' })
  @ApiResponse({ status: 200, description: 'Alert resolved' })
  async resolveAlert(@Param('id') alertId: string) {
    const success = await this.accessLogger.resolveAlert(alertId, 'api-controller');

    if (success) {
      return { message: 'Alert resolved successfully' };
    } else {
      return { error: 'Failed to resolve alert' };
    }
  }

  @Get('statistics')
  @ApiOperation({ summary: 'Get access statistics' })
  @ApiQuery({ name: 'hours', required: false, description: 'Time range in hours' })
  @ApiResponse({ status: 200, description: 'Access statistics' })
  async getAccessStatistics(@Query('hours') hours?: string) {
    return this.accessLogger.getAccessStatistics(parseInt(hours || '24'));
  }

  @Get('health')
  @ApiOperation({ summary: 'Get secrets management system health' })
  @ApiResponse({ status: 200, description: 'System health status' })
  async getSystemHealth() {
    try {
      const secrets = await this.secretsService.getSecretsMetadata();
      const alerts = await this.accessLogger.getSecurityAlerts(false, 10);
      const rotationStatus = await this.rotationService.getRotationStatus();

      const criticalSecrets = rotationStatus.filter(s => s.needsRotation).length;
      const unresolvedAlerts = alerts.length;

      let status = 'healthy';
      if (unresolvedAlerts > 0 || criticalSecrets > 0) {
        status = 'warning';
      }
      if (unresolvedAlerts > 5 || criticalSecrets > 3) {
        status = 'critical';
      }

      return {
        status,
        secretsCount: secrets.length,
        activeSecrets: secrets.filter(s => s.isActive && !s.emergencyRevoked).length,
        revokedSecrets: secrets.filter(s => s.emergencyRevoked).length,
        secretsNeedingRotation: criticalSecrets,
        unresolvedAlerts,
        lastChecked: new Date(),
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message,
        lastChecked: new Date(),
      };
    }
  }
}