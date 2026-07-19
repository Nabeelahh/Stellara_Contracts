import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AppService } from './app.service';

@ApiTags('App')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  /**
   * Root health-ping endpoint.
   * Returns a simple greeting wrapped in the standard response envelope.
   */
  @Get()
  @ApiOperation({ summary: 'Root ping endpoint' })
  @ApiResponse({
    status: 200,
    description: 'API is running',
    schema: {
      properties: {
        success: { type: 'boolean', example: true },
        statusCode: { type: 'number', example: 200 },
        data: {
          type: 'object',
          properties: {
            message: { type: 'string', example: 'Hello World!' },
          },
        },
        timestamp: { type: 'string', format: 'date-time' },
        path: { type: 'string', example: '/' },
      },
    },
  })
  getHello(): { message: string } {
    return { message: this.appService.getHello() };
  }
}
