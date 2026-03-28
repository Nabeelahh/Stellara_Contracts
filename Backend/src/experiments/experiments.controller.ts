import { Controller, Post, Body, Get, Param, Patch, Query } from '@nestjs/common';
import { ExperimentsService } from './experiments.service';
import { ExperimentStatus, Prisma } from '@prisma/client';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('experiments')
@Controller('experiments')
export class ExperimentsController {
  constructor(private readonly experimentsService: ExperimentsService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new experiment' })
  async createExperiment(@Body() data: Prisma.ExperimentCreateInput) {
    return this.experimentsService.createExperiment(data);
  }

  @Patch(':key/status')
  @ApiOperation({ summary: 'Update experiment status' })
  async updateStatus(@Param('key') key: string, @Body() body: { status: ExperimentStatus }) {
    return this.experimentsService.setExperimentStatus(key, body.status);
  }

  @Get(':key/analysis')
  @ApiOperation({ summary: 'Get experiment results with statistical analysis' })
  async getAnalysis(@Param('key') key: string) {
    return this.experimentsService.getDetailedAnalysis(key);
  }

  @Get('assignment')
  @ApiOperation({ summary: 'Get user assignment for an experiment' })
  async getAssignment(@Query('userId') userId: string, @Query('key') key: string) {
    return this.experimentsService.getAssignment(userId, key);
  }

  @Post('event')
  @ApiOperation({ summary: 'Track experiment event' })
  async trackEvent(
    @Body() body: { userId: string; key: string; eventName: string; value?: number },
  ) {
    return this.experimentsService.trackEvent(body.userId, body.key, body.eventName, body.value);
  }
}
