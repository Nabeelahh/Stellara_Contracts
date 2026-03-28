import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { EncryptionService } from '../services/encryption.service';
import { RequiresEncryption } from '../guards/encryption.guard';

@ApiTags('encryption')
@Controller('encryption')
@RequiresEncryption()
export class EncryptionController {
  constructor(private readonly encryptionService: EncryptionService) {}

  @Post('encrypt')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Encrypt sensitive data' })
  @ApiResponse({ status: 200, description: 'Data encrypted successfully' })
  @ApiResponse({ status: 400, description: 'Encryption failed' })
  async encryptData(@Body() body: { data: string; fieldType: string }): Promise<any> {
    try {
      const result = await this.encryptionService.encryptField(body.data, body.fieldType);
      return {
        success: true,
        encryptedData: result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Post('decrypt')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Decrypt sensitive data' })
  @ApiResponse({ status: 200, description: 'Data decrypted successfully' })
  @ApiResponse({ status: 400, description: 'Decryption failed' })
  async decryptData(
    @Body() body: { encryptedData: string; iv: string; keyId: string; fieldType: string },
  ): Promise<any> {
    try {
      const result = await this.encryptionService.decryptField(
        body.encryptedData,
        body.iv,
        body.keyId,
        body.fieldType,
      );
      return {
        success: true,
        decryptedData: result.decryptedData,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Post('keys/rotate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Rotate encryption keys' })
  @ApiResponse({ status: 200, description: 'Key rotated successfully' })
  @ApiResponse({ status: 500, description: 'Key rotation failed' })
  async rotateKeys(): Promise<any> {
    try {
      const newKey = await this.encryptionService.rotateKeys();
      return {
        success: true,
        newKey: {
          id: newKey.id,
          algorithm: newKey.algorithm,
          keySize: newKey.keySize,
          createdAt: newKey.createdAt,
          expiresAt: newKey.expiresAt,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Get('keys')
  @ApiOperation({ summary: 'Get all encryption keys' })
  @ApiResponse({ status: 200, description: 'List of encryption keys' })
  async getKeys(): Promise<any> {
    const keys = this.encryptionService.getAllKeys();
    return {
      success: true,
      keys: keys.map((key) => ({
        id: key.id,
        algorithm: key.algorithm,
        keySize: key.keySize,
        createdAt: key.createdAt,
        expiresAt: key.expiresAt,
        isRevoked: key.isRevoked,
        lastUsedAt: key.lastUsedAt,
      })),
    };
  }

  @Get('keys/active')
  @ApiOperation({ summary: 'Get active encryption key' })
  @ApiResponse({ status: 200, description: 'Active encryption key details' })
  async getActiveKey(): Promise<any> {
    try {
      const activeKey = this.encryptionService.getActiveKey();
      return {
        success: true,
        activeKey: {
          id: activeKey.id,
          algorithm: activeKey.algorithm,
          keySize: activeKey.keySize,
          createdAt: activeKey.createdAt,
          expiresAt: activeKey.expiresAt,
          lastUsedAt: activeKey.lastUsedAt,
        },
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Put('keys/:keyId/revoke')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Revoke an encryption key' })
  @ApiResponse({ status: 200, description: 'Key revoked successfully' })
  @ApiResponse({ status: 404, description: 'Key not found' })
  async revokeKey(@Param('keyId') keyId: string): Promise<any> {
    const success = await this.encryptionService.revokeKey(keyId);
    return {
      success,
      message: success ? `Key ${keyId} revoked successfully` : `Failed to revoke key ${keyId}`,
    };
  }

  @Get('status')
  @ApiOperation({ summary: 'Get encryption service status' })
  @ApiResponse({ status: 200, description: 'Encryption service status' })
  async getStatus(): Promise<any> {
    const status = this.encryptionService.getEncryptionStatus();
    const schedule = this.encryptionService.getKeyRotationSchedule();

    return {
      success: true,
      status,
      schedule,
    };
  }

  @Get('compliance')
  @ApiOperation({ summary: 'Validate encryption compliance' })
  @ApiResponse({ status: 200, description: 'Compliance validation results' })
  async getCompliance(): Promise<any> {
    const compliance = await this.encryptionService.validateEncryptionCompliance();

    return {
      success: true,
      compliance,
    };
  }

  @Get('audit-logs')
  @ApiOperation({ summary: 'Get encryption audit logs' })
  @ApiResponse({ status: 200, description: 'Audit logs' })
  async getAuditLogs(@Param('limit') limit?: string): Promise<any> {
    const limitNum = limit ? parseInt(limit) : 100;
    const logs = this.encryptionService.getAuditLogs(limitNum);

    return {
      success: true,
      logs: logs.map((log) => ({
        id: log.id,
        keyId: log.keyId,
        userId: log.userId,
        action: log.action,
        field: log.field,
        table: log.table,
        timestamp: log.timestamp,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent,
        success: log.success,
        error: log.error,
        processingTime: log.processingTime,
      })),
    };
  }

  // Convenience endpoints for common field types
  @Post('encrypt/email')
  @ApiOperation({ summary: 'Encrypt email address' })
  async encryptEmail(@Body() body: { email: string }): Promise<any> {
    const result = await this.encryptionService.encryptEmail(body.email);
    return { success: true, encryptedData: result };
  }

  @Post('encrypt/phone')
  @ApiOperation({ summary: 'Encrypt phone number' })
  async encryptPhone(@Body() body: { phone: string }): Promise<any> {
    const result = await this.encryptionService.encryptPhone(body.phone);
    return { success: true, encryptedData: result };
  }

  @Post('encrypt/ssn')
  @ApiOperation({ summary: 'Encrypt SSN' })
  async encryptSSN(@Body() body: { ssn: string }): Promise<any> {
    const result = await this.encryptionService.encryptSSN(body.ssn);
    return { success: true, encryptedData: result };
  }

  @Post('encrypt/credit-card')
  @ApiOperation({ summary: 'Encrypt credit card number' })
  async encryptCreditCard(@Body() body: { cardNumber: string }): Promise<any> {
    const result = await this.encryptionService.encryptCreditCard(body.cardNumber);
    return { success: true, encryptedData: result };
  }
}
