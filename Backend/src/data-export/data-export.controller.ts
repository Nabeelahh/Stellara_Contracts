import {
  Controller,
  Get,
  Post,
  Delete,
  Query,
  Body,
  Param,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  ParseUUIDPipe,
  Res,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Response } from 'express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { DataExportService } from './data-export.service';
import {
  CreateExportDto,
  ExportStatusDto,
  DownloadExportDto,
  ExportListQueryDto,
} from './dto/data-export.dto';
import { ExportJob } from './entities/export-job.entity';

@ApiTags('Data Export')
@Controller('data-export')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class DataExportController {
  constructor(private readonly dataExportService: DataExportService) {}

  @Post('initiate')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Initiate a new data export' })
  @ApiResponse({ status: 201, description: 'Export initiated successfully', type: ExportJob })
  @ApiResponse({ status: 400, description: 'Bad request' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async initiateExport(
    @Request() req: any,
    @Body() createExportDto: CreateExportDto,
  ): Promise<ExportJob> {
    return await this.dataExportService.initiateExport(req.user.userId, createExportDto);
  }

  @Get('status/:exportId')
  @ApiOperation({ summary: 'Get export job status' })
  @ApiResponse({ status: 200, description: 'Export status retrieved', type: ExportJob })
  @ApiResponse({ status: 404, description: 'Export not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getExportStatus(
    @Request() req: any,
    @Param('exportId', ParseUUIDPipe) exportId: string,
  ): Promise<ExportJob> {
    return await this.dataExportService.getExportStatus(req.user.userId, exportId);
  }

  @Post('download')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get download URL for completed export' })
  @ApiResponse({ status: 200, description: 'Download URL generated' })
  @ApiResponse({ status: 400, description: 'Export not ready for download' })
  @ApiResponse({ status: 404, description: 'Export not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getDownloadUrl(
    @Request() req: any,
    @Body() downloadDto: DownloadExportDto,
  ): Promise<{ downloadUrl: string; expiresAt: Date }> {
    return await this.dataExportService.downloadExport(req.user.userId, downloadDto);
  }

  @Get('download-file/:exportId')
  @ApiOperation({ summary: 'Download export file directly' })
  @ApiResponse({ status: 200, description: 'File downloaded successfully' })
  @ApiResponse({ status: 404, description: 'Export not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async downloadFile(
    @Request() req: any,
    @Param('exportId', ParseUUIDPipe) exportId: string,
    @Query('token') token: string,
    @Res() res: Response,
  ): Promise<void> {
    const exportJob = await this.dataExportService.getExportStatus(req.user.userId, exportId);

    if (exportJob.status !== 'completed') {
      res.status(400).json({ message: 'Export not ready for download' });
      return;
    }

    // In a real implementation, you would validate the token here
    // and serve the file from the file system or cloud storage

    res.status(200).json({
      message: 'File download endpoint',
      exportId,
      filePath: exportJob.filePath,
    });
  }

  @Get('list')
  @ApiOperation({ summary: 'Get list of user exports with filtering' })
  @ApiResponse({ status: 200, description: 'Export list retrieved' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getUserExports(
    @Request() req: any,
    @Query() query: ExportListQueryDto,
  ): Promise<{ exports: ExportJob[]; total: number }> {
    return await this.dataExportService.getUserExports(req.user.userId, query);
  }

  @Delete(':exportId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete an export job and its files' })
  @ApiResponse({ status: 204, description: 'Export deleted successfully' })
  @ApiResponse({ status: 404, description: 'Export not found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async deleteExport(
    @Request() req: any,
    @Param('exportId', ParseUUIDPipe) exportId: string,
  ): Promise<void> {
    await this.dataExportService.deleteExport(req.user.userId, exportId);
  }
}
