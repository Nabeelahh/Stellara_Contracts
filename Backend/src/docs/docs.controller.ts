import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('docs')
@Controller()
export class DocsController {
  @Get('docs-info')
  @ApiOperation({
    summary: 'Get API documentation info',
    description: 'Returns information about the API documentation and available endpoints',
  })
  @ApiResponse({
    status: 200,
    description: 'Documentation info',
    schema: {
      type: 'object',
      properties: {
        swaggerUi: { type: 'string', example: '/docs' },
        openApiJson: { type: 'string', example: '/openapi.json' },
        version: { type: 'string', example: '1.0.0' },
        authentication: {
          type: 'object',
          properties: {
            type: { type: 'string', example: 'JWT' },
            header: { type: 'string', example: 'Authorization: Bearer <token>' },
            cookie: { type: 'string', example: 'access_token (HTTP-only)' },
          },
        },
      },
    },
  })
  getDocsInfo() {
    return {
      swaggerUi: '/docs',
      openApiJson: '/openapi.json',
      version: '1.0.0',
      title: 'Stellara API Documentation',
      description: 'Interactive API documentation with Swagger UI',
      authentication: {
        type: 'JWT',
        description: 'Most endpoints require authentication via JWT token',
        methods: {
          header: 'Authorization: Bearer <token>',
          cookie: 'access_token (HTTP-only cookie)',
        },
        loginEndpoint: '/auth/login',
      },
      endpoints: {
        auth: '/auth',
        users: '/api/user',
        nonce: '/nonce',
        insurance: '/api/insurance',
        notifications: '/notifications',
        storage: '/projects',
        config: '/config',
        encryption: '/encryption',
      },
    };
  }
}
