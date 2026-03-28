import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';
import { HealthCheckDto } from './common/dto/common.dto';

@ApiTags('health')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({
    summary: 'Root endpoint',
    description: 'Returns a welcome message for the API',
  })
  @ApiResponse({
    status: 200,
    description: 'Welcome message',
    type: String,
  })
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('health')
  @ApiOperation({
    summary: 'Health check',
    description: 'Returns the current health status of the API server',
  })
  @ApiResponse({
    status: 200,
    description: 'Health status',
    type: HealthCheckDto,
  })
  getHealth(): HealthCheckDto {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }
}
