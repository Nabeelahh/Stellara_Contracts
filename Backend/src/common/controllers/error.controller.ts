import { Controller, Get, Post, Body, HttpCode, HttpStatus, Headers } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { ERROR_CODES } from '../exceptions/error-codes';

@ApiTags('errors')
@Controller('errors')
export class ErrorController {
  constructor(private readonly configService: ConfigService) {}

  @Get('codes')
  @ApiOperation({ summary: 'Get all error codes and messages' })
  @ApiResponse({ status: 200, description: 'Error codes reference' })
  getErrorCodes(): any {
    return {
      success: true,
      data: {
        categories: {
          validation: {
            range: '1000-1099',
            description: 'Validation and input errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          authentication: {
            range: '1100-1199',
            description: 'Authentication and authorization errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          authorization: {
            range: '1200-1299',
            description: 'Permission and access control errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          notFound: {
            range: '1300-1399',
            description: 'Resource not found errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          conflict: {
            range: '1400-1499',
            description: 'Resource conflict and state errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          rateLimit: {
            range: '1500-1599',
            description: 'Rate limiting and throttling errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          businessLogic: {
            range: '1600-1699',
            description: 'Business logic and domain errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          database: {
            range: '1700-1799',
            description: 'Database and persistence errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          external: {
            range: '1800-1899',
            description: 'External service and integration errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          system: {
            range: '1900-1999',
            description: 'System and infrastructure errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E1')),
          },
          security: {
            range: '2000-2099',
            description: 'Security and attack detection errors',
            codes: Object.keys(ERROR_CODES).filter((code) => code.startsWith('E2')),
          },
        },
        codes: ERROR_CODES,
        messages: this.getErrorMessages(),
      },
    };
  }

  @Get('health')
  @ApiOperation({ summary: 'Get error handling health status' })
  @ApiResponse({ status: 200, description: 'Error handling system health' })
  getHealthStatus(): any {
    const isDevelopment = this.configService.get('NODE_ENV') !== 'production';

    return {
      success: true,
      data: {
        status: 'healthy',
        features: {
          globalExceptionFilter: true,
          validationFilter: true,
          errorResponseInterceptor: true,
          structuredLogging: true,
          securityHeaders: true,
          monitoring: isDevelopment,
        },
        configuration: {
          environment: this.configService.get('NODE_ENV'),
          logLevel: this.configService.get('LOG_LEVEL', 'info'),
          monitoringEnabled: !!process.env.SENTRY_DSN,
        },
      },
    };
  }

  @Post('test')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Test error handling' })
  @ApiResponse({ status: 200, description: 'Error test executed' })
  async testError(
    @Body() body: { type: string; message?: string },
    @Headers() headers: Record<string, string>,
  ): Promise<any> {
    // For testing different error types
    switch (body.type) {
      case 'validation':
        throw new Error('Test validation error');
      case 'authentication':
        throw new Error('Test authentication error');
      case 'authorization':
        throw new Error('Test authorization error');
      case 'notFound':
        throw new Error('Test not found error');
      case 'businessLogic':
        throw new Error('Test business logic error');
      case 'database':
        throw new Error('Test database error');
      case 'external':
        throw new Error('Test external service error');
      case 'system':
        throw new Error('Test system error');
      default:
        throw new Error(body.message || 'Test error');
    }
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get error statistics' })
  @ApiResponse({ status: 200, description: 'Error statistics' })
  getErrorStats(): any {
    // This would typically query error logs from database
    // For now, return mock data
    return {
      success: true,
      data: {
        totalErrors: 0,
        errorsByCategory: {
          validation: 0,
          authentication: 0,
          authorization: 0,
          notFound: 0,
          conflict: 0,
          rateLimit: 0,
          businessLogic: 0,
          database: 0,
          external: 0,
          system: 0,
          security: 0,
        },
        errorsByStatus: {
          '400': 0,
          '401': 0,
          '403': 0,
          '404': 0,
          '409': 0,
          '429': 0,
          '500': 0,
          '503': 0,
        },
        recentErrors: [],
        averageResponseTime: 0,
        errorRate: 0,
      },
    };
  }

  private getErrorMessages(): Record<string, string> {
    const messages: Record<string, string> = {};

    // Map all error codes to messages
    Object.entries(ERROR_CODES).forEach(([code, message]) => {
      messages[code] = message;
    });

    return messages;
  }
}
