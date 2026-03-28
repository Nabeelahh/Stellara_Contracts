import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { join } from 'path';
import { promises as fs } from 'fs';
import { v4 as uuidv4 } from 'uuid';
import * as archiver from 'archiver';
import * as crypto from 'crypto';
import { sign } from 'aws4';

import { ExportJob, ExportStatus, ExportType, ExportFormat } from './entities/export-job.entity';
import { User } from '../auth/entities/user.entity';
import { TransactionRecord } from '../contract-interaction/entities/transaction-record.entity';
import { ContractMetadata } from '../contract-interaction/entities/contract-metadata.entity';
import { Workflow } from '../workflow/entities/workflow.entity';
import { AuditLog } from '../audit/audit.entity';
import { Consent } from '../gdpr/entities/consent.entity';
import { VoiceJob } from '../voice/entities/voice-job.entity';

import { AuditService } from '../audit/audit.service';
import {
  CreateExportDto,
  ExportStatusDto,
  DownloadExportDto,
  ExportListQueryDto,
} from './dto/data-export.dto';

@Injectable()
export class DataExportService {
  private readonly logger = new Logger(DataExportService.name);
  private readonly exportDir: string;

  constructor(
    @InjectRepository(ExportJob)
    private exportJobRepository: Repository<ExportJob>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(TransactionRecord)
    private transactionRepository: Repository<TransactionRecord>,
    @InjectRepository(ContractMetadata)
    private contractRepository: Repository<ContractMetadata>,
    @InjectRepository(Workflow)
    private workflowRepository: Repository<Workflow>,
    @InjectRepository(AuditLog)
    private auditLogRepository: Repository<AuditLog>,
    @InjectRepository(Consent)
    private consentRepository: Repository<Consent>,
    @InjectRepository(VoiceJob)
    private voiceJobRepository: Repository<VoiceJob>,
    private configService: ConfigService,
    private dataSource: DataSource,
    private auditService: AuditService,
  ) {
    this.exportDir = this.configService.get<string>('EXPORT_DIR') || './exports';
    this.ensureExportDirectory();
  }

  async initiateExport(userId: string, createExportDto: CreateExportDto): Promise<ExportJob> {
    const exportJob = this.exportJobRepository.create({
      userId,
      exportType: createExportDto.exportType,
      format: createExportDto.format,
      filters: createExportDto.filters,
      scheduledFor: createExportDto.scheduledFor,
      metadata: {
        includeSensitiveData: createExportDto.includeSensitiveData || false,
        requestedAt: new Date(),
      },
    });

    const savedJob = await this.exportJobRepository.save(exportJob);

    await this.auditService.log({
      userId,
      action: 'EXPORT_INITIATED',
      resource: `ExportJob:${savedJob.id}`,
      details: {
        exportType: createExportDto.exportType,
        format: createExportDto.format,
        filters: createExportDto.filters,
      },
    });

    if (!createExportDto.scheduledFor) {
      await this.processExport(savedJob.id);
    }

    return savedJob;
  }

  async getExportStatus(userId: string, exportId: string): Promise<ExportJob> {
    const exportJob = await this.exportJobRepository.findOne({
      where: { id: exportId, userId },
    });

    if (!exportJob) {
      throw new NotFoundException(`Export job ${exportId} not found`);
    }

    return exportJob;
  }

  async downloadExport(
    userId: string,
    downloadDto: DownloadExportDto,
  ): Promise<{ downloadUrl: string; expiresAt: Date }> {
    const exportJob = await this.exportJobRepository.findOne({
      where: { id: downloadDto.exportId, userId },
    });

    if (!exportJob) {
      throw new NotFoundException(`Export job ${downloadDto.exportId} not found`);
    }

    if (exportJob.status !== ExportStatus.COMPLETED) {
      throw new BadRequestException(
        `Export is not ready for download. Current status: ${exportJob.status}`,
      );
    }

    if (exportJob.expiresAt && exportJob.expiresAt < new Date()) {
      throw new BadRequestException('Export download link has expired');
    }

    if (downloadDto.regenerateUrl || !exportJob.downloadUrl) {
      const downloadUrl = await this.generateSignedDownloadUrl(exportJob);
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24);

      exportJob.downloadUrl = downloadUrl;
      exportJob.expiresAt = expiresAt;
      await this.exportJobRepository.save(exportJob);

      return { downloadUrl, expiresAt };
    }

    return {
      downloadUrl: exportJob.downloadUrl,
      expiresAt: exportJob.expiresAt,
    };
  }

  async getUserExports(
    userId: string,
    query: ExportListQueryDto,
  ): Promise<{ exports: ExportJob[]; total: number }> {
    const queryBuilder = this.exportJobRepository
      .createQueryBuilder('export')
      .where('export.userId = :userId', { userId });

    if (query.exportType) {
      queryBuilder.andWhere('export.exportType = :exportType', { exportType: query.exportType });
    }

    if (query.status) {
      queryBuilder.andWhere('export.status = :status', { status: query.status });
    }

    if (query.startDate) {
      queryBuilder.andWhere('export.createdAt >= :startDate', { startDate: query.startDate });
    }

    if (query.endDate) {
      queryBuilder.andWhere('export.createdAt <= :endDate', { endDate: query.endDate });
    }

    queryBuilder.orderBy('export.createdAt', 'DESC');
    queryBuilder.skip((query.page - 1) * query.limit).take(query.limit);

    const [exports, total] = await queryBuilder.getManyAndCount();

    return { exports, total };
  }

  async deleteExport(userId: string, exportId: string): Promise<void> {
    const exportJob = await this.exportJobRepository.findOne({
      where: { id: exportId, userId },
    });

    if (!exportJob) {
      throw new NotFoundException(`Export job ${exportId} not found`);
    }

    if (exportJob.filePath) {
      try {
        await fs.unlink(exportJob.filePath);
      } catch (error) {
        this.logger.warn(`Failed to delete export file: ${error.message}`);
      }
    }

    await this.exportJobRepository.remove(exportJob);

    await this.auditService.log({
      userId,
      action: 'EXPORT_DELETED',
      resource: `ExportJob:${exportId}`,
      details: { exportType: exportJob.exportType },
    });
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async processScheduledExports(): Promise<void> {
    const scheduledExports = await this.exportJobRepository.find({
      where: {
        status: ExportStatus.PENDING,
        scheduledFor: {
          $lte: new Date(),
        },
      },
      take: 10,
    });

    for (const exportJob of scheduledExports) {
      await this.processExport(exportJob.id);
    }
  }

  @Cron(CronExpression.EVERY_HOUR)
  async cleanupExpiredExports(): Promise<void> {
    const expiredExports = await this.exportJobRepository.find({
      where: {
        status: ExportStatus.COMPLETED,
        expiresAt: {
          $lt: new Date(),
        },
      },
    });

    for (const exportJob of expiredExports) {
      if (exportJob.filePath) {
        try {
          await fs.unlink(exportJob.filePath);
        } catch (error) {
          this.logger.warn(`Failed to delete expired export file: ${error.message}`);
        }
      }

      exportJob.status = ExportStatus.EXPIRED;
      await this.exportJobRepository.save(exportJob);
    }
  }

  private async processExport(exportId: string): Promise<void> {
    const exportJob = await this.exportJobRepository.findOne({
      where: { id: exportId },
    });

    if (!exportJob) {
      this.logger.error(`Export job ${exportId} not found`);
      return;
    }

    try {
      exportJob.status = ExportStatus.PROCESSING;
      exportJob.progressPercentage = 0;
      await this.exportJobRepository.save(exportJob);

      const filePath = await this.generateExportFile(exportJob);
      const fileSize = (await fs.stat(filePath)).size;

      exportJob.status = ExportStatus.COMPLETED;
      exportJob.filePath = filePath;
      exportJob.fileSize = BigInt(fileSize);
      exportJob.completedAt = new Date();
      exportJob.progressPercentage = 100;

      const downloadUrl = await this.generateSignedDownloadUrl(exportJob);
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24);

      exportJob.downloadUrl = downloadUrl;
      exportJob.expiresAt = expiresAt;

      await this.exportJobRepository.save(exportJob);

      await this.sendCompletionNotification(exportJob);
    } catch (error) {
      this.logger.error(
        `Export processing failed for job ${exportId}: ${error.message}`,
        error.stack,
      );

      exportJob.status = ExportStatus.FAILED;
      exportJob.errorData = {
        message: error.message,
        stack: error.stack,
      };
      await this.exportJobRepository.save(exportJob);

      await this.sendFailureNotification(exportJob, error);
    }
  }

  private async generateExportFile(exportJob: ExportJob): Promise<string> {
    const fileName = `${exportJob.exportType}_${exportJob.id}_${Date.now()}.${exportJob.format}`;
    const filePath = join(this.exportDir, fileName);

    const data = await this.fetchExportData(exportJob);

    if (exportJob.format === ExportFormat.JSON) {
      await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
    } else if (exportJob.format === ExportFormat.CSV) {
      await this.writeCsvFile(filePath, data, exportJob.exportType);
    } else {
      throw new BadRequestException(`Unsupported export format: ${exportJob.format}`);
    }

    return filePath;
  }

  private async fetchExportData(exportJob: ExportJob): Promise<any> {
    const userId = exportJob.userId;
    const filters = exportJob.filters || {};

    switch (exportJob.exportType) {
      case ExportType.USER_DATA:
        return await this.exportUserData(userId, filters);
      case ExportType.TRANSACTIONS:
        return await this.exportTransactions(userId, filters);
      case ExportType.CONTRACTS:
        return await this.exportContracts(userId, filters);
      case ExportType.WORKFLOWS:
        return await this.exportWorkflows(userId, filters);
      case ExportType.AUDIT_LOGS:
        return await this.exportAuditLogs(userId, filters);
      case ExportType.ALL_DATA:
        return await this.exportAllUserData(userId, filters);
      default:
        throw new BadRequestException(`Unsupported export type: ${exportJob.exportType}`);
    }
  }

  private async exportUserData(userId: string, filters: any): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['walletBindings', 'refreshTokens'],
    });

    if (!user) {
      throw new NotFoundException(`User ${userId} not found`);
    }

    const consents = await this.consentRepository.find({
      where: { userId },
    });

    return {
      user: this.sanitizeUserData(user),
      walletBindings: user.walletBindings || [],
      refreshTokens: user.refreshTokens || [],
      consents: consents,
      exportedAt: new Date(),
    };
  }

  private async exportTransactions(userId: string, filters: any): Promise<any> {
    const queryBuilder = this.transactionRepository
      .createQueryBuilder('transaction')
      .where('transaction.userId = :userId', { userId });

    if (filters.startDate) {
      queryBuilder.andWhere('transaction.createdAt >= :startDate', {
        startDate: filters.startDate,
      });
    }

    if (filters.endDate) {
      queryBuilder.andWhere('transaction.createdAt <= :endDate', { endDate: filters.endDate });
    }

    if (filters.status) {
      queryBuilder.andWhere('transaction.status = :status', { status: filters.status });
    }

    const transactions = await queryBuilder.getMany();

    return {
      transactions,
      exportedAt: new Date(),
      filters,
    };
  }

  private async exportContracts(userId: string, filters: any): Promise<any> {
    const queryBuilder = this.contractRepository
      .createQueryBuilder('contract')
      .where('contract.userId = :userId', { userId });

    if (filters.status) {
      queryBuilder.andWhere('contract.status = :status', { status: filters.status });
    }

    const contracts = await queryBuilder.getMany();

    return {
      contracts,
      exportedAt: new Date(),
      filters,
    };
  }

  private async exportWorkflows(userId: string, filters: any): Promise<any> {
    const queryBuilder = this.workflowRepository
      .createQueryBuilder('workflow')
      .where('workflow.userId = :userId', { userId });

    if (filters.status) {
      queryBuilder.andWhere('workflow.status = :status', { status: filters.status });
    }

    const workflows = await queryBuilder.getMany();

    return {
      workflows,
      exportedAt: new Date(),
      filters,
    };
  }

  private async exportAuditLogs(userId: string, filters: any): Promise<any> {
    const queryBuilder = this.auditLogRepository
      .createQueryBuilder('audit')
      .where('audit.userId = :userId', { userId });

    if (filters.startDate) {
      queryBuilder.andWhere('audit.createdAt >= :startDate', { startDate: filters.startDate });
    }

    if (filters.endDate) {
      queryBuilder.andWhere('audit.createdAt <= :endDate', { endDate: filters.endDate });
    }

    const auditLogs = await queryBuilder.getMany();

    return {
      auditLogs,
      exportedAt: new Date(),
      filters,
    };
  }

  private async exportAllUserData(userId: string, filters: any): Promise<any> {
    const [userData, transactions, contracts, workflows, auditLogs] = await Promise.all([
      this.exportUserData(userId, filters),
      this.exportTransactions(userId, filters),
      this.exportContracts(userId, filters),
      this.exportWorkflows(userId, filters),
      this.exportAuditLogs(userId, filters),
    ]);

    return {
      ...userData,
      ...transactions,
      ...contracts,
      ...workflows,
      ...auditLogs,
      exportType: 'all_data',
      exportedAt: new Date(),
    };
  }

  private sanitizeUserData(user: User): any {
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
  }

  private async writeCsvFile(filePath: string, data: any, exportType: ExportType): Promise<void> {
    // CSV implementation would go here
    // For now, we'll write as JSON since CSV conversion is complex
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
  }

  private async generateSignedDownloadUrl(exportJob: ExportJob): Promise<string> {
    const baseUrl = this.configService.get<string>('BASE_URL') || 'http://localhost:3000';
    const token = this.generateDownloadToken(exportJob);
    return `${baseUrl}/api/data-export/download-file/${exportJob.id}?token=${token}`;
  }

  private generateDownloadToken(exportJob: ExportJob): string {
    const payload = {
      exportId: exportJob.id,
      userId: exportJob.userId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).getTime(), // 24 hours
    };

    return crypto
      .createHash('sha256')
      .update(JSON.stringify(payload) + this.configService.get<string>('EXPORT_SECRET'))
      .digest('hex');
  }

  private async sendCompletionNotification(exportJob: ExportJob): Promise<void> {
    if (exportJob.notificationSent) return;

    // Email notification implementation would go here
    this.logger.log(`Export ${exportJob.id} completed for user ${exportJob.userId}`);

    exportJob.notificationSent = true;
    await this.exportJobRepository.save(exportJob);
  }

  private async sendFailureNotification(exportJob: ExportJob, error: Error): Promise<void> {
    // Email notification implementation would go here
    this.logger.error(
      `Export ${exportJob.id} failed for user ${exportJob.userId}: ${error.message}`,
    );
  }

  private async ensureExportDirectory(): Promise<void> {
    try {
      await fs.mkdir(this.exportDir, { recursive: true });
    } catch (error) {
      this.logger.error(`Failed to create export directory: ${error.message}`);
    }
  }
}
