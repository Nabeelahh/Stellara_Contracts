import {
  Injectable,
  Logger,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, SelectQueryBuilder } from 'typeorm';
import { JwtService } from '@nestjs/jwt';

import { User } from '../auth/entities/user.entity';
import {
  TransactionRecord,
  TransactionStatus,
} from '../contract-interaction/entities/transaction-record.entity';
import {
  ContractMetadata,
  ContractStatus,
} from '../contract-interaction/entities/contract-metadata.entity';
import { Workflow } from '../workflow/entities/workflow.entity';
import { AuditLog } from '../audit/audit.entity';
import { Consent } from '../gdpr/entities/consent.entity';
import { VoiceJob } from '../voice/entities/voice-job.entity';

import { SearchService } from '../search/search.service';
import { AuditService } from '../audit/audit.service';
import { AdvancedCacheService } from '../cache/advanced-cache.service';

import {
  UserFilterDto,
  UserManagementDto,
  ImpersonationDto,
  SystemMetricsDto,
  TenantUsageDto,
  HealthCheckDto,
  AuditLogQueryDto,
  ManualOverrideDto,
  UserStatus,
  SystemHealthStatus,
} from './dto/admin.dto';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);
  private readonly impersonationTokens = new Map<string, { userId: string; expiresAt: Date }>();

  constructor(
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
    private searchService: SearchService,
    private auditService: AuditService,
    private jwtService: JwtService,
    private readonly cache: AdvancedCacheService,
  ) {}

  async getUsers(
    filter: UserFilterDto,
    page = 1,
    limit = 20,
  ): Promise<{ users: User[]; total: number }> {
    const queryBuilder = this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.walletBindings', 'walletBindings')
      .leftJoinAndSelect('user.refreshTokens', 'refreshTokens');

    if (filter.search) {
      queryBuilder.where(
        '(user.username ILIKE :search OR user.email ILIKE :search OR user.id ILIKE :search)',
        { search: `%${filter.search}%` },
      );
    }

    if (filter.status) {
      queryBuilder.andWhere('user.status = :status', { status: filter.status });
    }

    if (filter.role) {
      queryBuilder.andWhere('user.role = :role', { role: filter.role });
    }

    if (filter.tenantId) {
      queryBuilder.andWhere('user.tenantId = :tenantId', { tenantId: filter.tenantId });
    }

    if (filter.startDate) {
      queryBuilder.andWhere('user.createdAt >= :startDate', { startDate: filter.startDate });
    }

    if (filter.endDate) {
      queryBuilder.andWhere('user.createdAt <= :endDate', { endDate: filter.endDate });
    }

    queryBuilder.orderBy('user.createdAt', 'DESC');
    queryBuilder.skip((page - 1) * limit).take(limit);

    const [users, total] = await queryBuilder.getManyAndCount();

    return { users, total };
  }

  async updateUser(
    userId: string,
    updateData: UserManagementDto,
    adminUserId: string,
  ): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`User ${userId} not found`);
    }

    const previousStatus = user.status;
    Object.assign(user, updateData);
    await this.userRepository.save(user);

    await this.auditService.log({
      userId: adminUserId,
      action: 'USER_UPDATE',
      resource: `User:${userId}`,
      details: {
        previousStatus,
        newStatus: user.status,
        updateData,
        impersonatedUserId: userId,
      },
    });

    return user;
  }

  async suspendUser(userId: string, reason: string, adminUserId: string): Promise<User> {
    return await this.updateUser(userId, { status: UserStatus.SUSPENDED }, adminUserId);
  }

  async activateUser(userId: string, adminUserId: string): Promise<User> {
    return await this.updateUser(userId, { status: UserStatus.ACTIVE }, adminUserId);
  }

  async impersonateUser(
    impersonationDto: ImpersonationDto,
    adminUserId: string,
  ): Promise<{ token: string; expiresAt: Date }> {
    const targetUser = await this.userRepository.findOne({
      where: { id: impersonationDto.targetUserId },
    });
    if (!targetUser) {
      throw new NotFoundException(`Target user ${impersonationDto.targetUserId} not found`);
    }

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + impersonationDto.durationHours);

    const payload = {
      userId: targetUser.id,
      email: targetUser.email,
      role: targetUser.role,
      isImpersonation: true,
      originalUserId: adminUserId,
      exp: Math.floor(expiresAt.getTime() / 1000),
    };

    const token = this.jwtService.sign(payload);

    this.impersonationTokens.set(token, { userId: targetUser.id, expiresAt });

    await this.auditService.log({
      userId: adminUserId,
      action: 'USER_IMPERSONATION',
      resource: `User:${targetUser.id}`,
      details: {
        reason: impersonationDto.reason,
        durationHours: impersonationDto.durationHours,
        expiresAt,
      },
    });

    return { token, expiresAt };
  }

  async getSystemMetrics(): Promise<SystemMetricsDto> {
    const [
      totalUsers,
      activeUsers,
      totalTransactions,
      totalContracts,
      totalWorkflows,
      systemUptime,
      memoryUsage,
      cpuUsage,
      diskUsage,
      databaseConnections,
      cacheHitRate,
      cacheEvictionRate,
    ] = await Promise.all([
      this.userRepository.count(),
      this.userRepository.count({ where: { status: UserStatus.ACTIVE } }),
      this.transactionRepository.count(),
      this.contractRepository.count(),
      this.workflowRepository.count(),
      this.getSystemUptime(),
      this.getMemoryUsage(),
      this.getCpuUsage(),
      this.getDiskUsage(),
      this.getDatabaseConnections(),
      this.getCacheHitRate(),
      this.getCacheEvictionRate(),
    ]);

    return {
      totalUsers,
      activeUsers,
      totalTransactions,
      totalContracts,
      totalWorkflows,
      systemUptime,
      memoryUsage,
      cpuUsage,
      diskUsage,
      databaseConnections,
      cacheHitRate,
      cacheEvictionRate,
    };
  }

  async getTenantUsage(): Promise<TenantUsageDto[]> {
    const tenantStats = await this.userRepository
      .createQueryBuilder('user')
      .select('user.tenantId', 'tenantId')
      .addSelect('COUNT(DISTINCT user.id)', 'userCount')
      .addSelect('COUNT(DISTINCT transactions.id)', 'transactionCount')
      .addSelect('COUNT(DISTINCT contracts.id)', 'contractCount')
      .leftJoin('user.transactions', 'transactions')
      .leftJoin('user.contracts', 'contracts')
      .where('user.tenantId IS NOT NULL')
      .groupBy('user.tenantId')
      .orderBy('userCount', 'DESC')
      .getRawMany();

    return tenantStats.map((stat) => ({
      tenantId: stat.tenantId,
      tenantName: `Tenant ${stat.tenantId}`,
      userCount: parseInt(stat.userCount),
      transactionCount: parseInt(stat.transactionCount),
      contractCount: parseInt(stat.contractCount),
      storageUsed: 0,
      apiCalls: 0,
      lastActivity: new Date(),
    }));
  }

  async getHealthCheck(): Promise<HealthCheckDto> {
    const services = await Promise.all([
      this.checkDatabaseHealth(),
      this.checkRedisHealth(),
      this.checkStellarHealth(),
      this.checkElasticsearchHealth(),
    ]);

    const overallStatus = services.some((s) => s.status === SystemHealthStatus.UNHEALTHY)
      ? SystemHealthStatus.UNHEALTHY
      : services.some((s) => s.status === SystemHealthStatus.DEGRADED)
        ? SystemHealthStatus.DEGRADED
        : SystemHealthStatus.HEALTHY;

    return {
      status: overallStatus,
      timestamp: new Date(),
      services,
      metrics: {
        uptime: await this.getSystemUptime(),
        memoryUsage: await this.getMemoryUsage(),
        cpuUsage: await this.getCpuUsage(),
        activeConnections: await this.getDatabaseConnections(),
      },
    };
  }

  async getAuditLogs(query: AuditLogQueryDto): Promise<{ logs: AuditLog[]; total: number }> {
    const queryBuilder = this.auditLogRepository
      .createQueryBuilder('audit')
      .leftJoinAndSelect('audit.user', 'user');

    if (query.userId) {
      queryBuilder.andWhere('audit.userId = :userId', { userId: query.userId });
    }

    if (query.action) {
      queryBuilder.andWhere('audit.action ILIKE :action', { action: `%${query.action}%` });
    }

    if (query.resource) {
      queryBuilder.andWhere('audit.resource ILIKE :resource', { resource: `%${query.resource}%` });
    }

    if (query.startDate) {
      queryBuilder.andWhere('audit.createdAt >= :startDate', { startDate: query.startDate });
    }

    if (query.endDate) {
      queryBuilder.andWhere('audit.createdAt <= :endDate', { endDate: query.endDate });
    }

    queryBuilder.orderBy('audit.createdAt', 'DESC');
    queryBuilder.skip((query.page - 1) * query.limit).take(query.limit);

    const [logs, total] = await queryBuilder.getManyAndCount();

    return { logs, total };
  }

  async performManualOverride(overrideDto: ManualOverrideDto, adminUserId: string): Promise<any> {
    await this.auditService.log({
      userId: adminUserId,
      action: 'MANUAL_OVERRIDE',
      resource: `${overrideDto.entityType}:${overrideDto.entityId}`,
      details: overrideDto,
    });

    switch (overrideDto.entityType) {
      case 'transaction':
        return await this.overrideTransaction(overrideDto);
      case 'contract':
        return await this.overrideContract(overrideDto);
      case 'user':
        return await this.overrideUser(overrideDto);
      case 'workflow':
        return await this.overrideWorkflow(overrideDto);
      default:
        throw new BadRequestException(`Unsupported entity type: ${overrideDto.entityType}`);
    }
  }

  private async overrideTransaction(overrideDto: ManualOverrideDto): Promise<any> {
    const transaction = await this.transactionRepository.findOne({
      where: { id: overrideDto.entityId },
    });

    if (!transaction) {
      throw new NotFoundException(`Transaction ${overrideDto.entityId} not found`);
    }

    switch (overrideDto.action) {
      case 'retry':
        transaction.status = TransactionStatus.PENDING;
        transaction.pollingAttempts = 0;
        return await this.transactionRepository.save(transaction);
      case 'fail':
        transaction.status = TransactionStatus.FAILED;
        transaction.errorData = { message: 'Manually failed by admin', reason: overrideDto.reason };
        return await this.transactionRepository.save(transaction);
      default:
        throw new BadRequestException(`Unsupported action: ${overrideDto.action}`);
    }
  }

  private async overrideContract(overrideDto: ManualOverrideDto): Promise<any> {
    const contract = await this.contractRepository.findOne({
      where: { id: overrideDto.entityId },
    });

    if (!contract) {
      throw new NotFoundException(`Contract ${overrideDto.entityId} not found`);
    }

    switch (overrideDto.action) {
      case 'activate':
        contract.status = ContractStatus.ACTIVE;
        return await this.contractRepository.save(contract);
      case 'deactivate':
        contract.status = ContractStatus.INACTIVE;
        return await this.contractRepository.save(contract);
      default:
        throw new BadRequestException(`Unsupported action: ${overrideDto.action}`);
    }
  }

  private async overrideUser(overrideDto: ManualOverrideDto): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { id: overrideDto.entityId },
    });

    if (!user) {
      throw new NotFoundException(`User ${overrideDto.entityId} not found`);
    }

    switch (overrideDto.action) {
      case 'reset_password':
        return { message: 'Password reset initiated', userId: user.id };
      case 'force_verify':
        user.emailVerified = true;
        return await this.userRepository.save(user);
      default:
        throw new BadRequestException(`Unsupported action: ${overrideDto.action}`);
    }
  }

  private async overrideWorkflow(overrideDto: ManualOverrideDto): Promise<any> {
    const workflow = await this.workflowRepository.findOne({
      where: { id: overrideDto.entityId },
    });

    if (!workflow) {
      throw new NotFoundException(`Workflow ${overrideDto.entityId} not found`);
    }

    switch (overrideDto.action) {
      case 'pause':
        return { message: 'Workflow paused', workflowId: workflow.id };
      case 'resume':
        return { message: 'Workflow resumed', workflowId: workflow.id };
      default:
        throw new BadRequestException(`Unsupported action: ${overrideDto.action}`);
    }
  }

  private async checkDatabaseHealth(): Promise<any> {
    try {
      const start = Date.now();
      await this.dataSource.query('SELECT 1');
      const responseTime = Date.now() - start;

      return {
        name: 'database',
        status: responseTime < 1000 ? SystemHealthStatus.HEALTHY : SystemHealthStatus.DEGRADED,
        responseTime,
        lastCheck: new Date(),
      };
    } catch (error) {
      return {
        name: 'database',
        status: SystemHealthStatus.UNHEALTHY,
        responseTime: 0,
        lastCheck: new Date(),
        error: error.message,
      };
    }
  }

  private async checkRedisHealth(): Promise<any> {
    try {
      const start = Date.now();
      await this.dataSource.query('SELECT 1');
      const responseTime = Date.now() - start;

      return {
        name: 'redis',
        status: responseTime < 500 ? SystemHealthStatus.HEALTHY : SystemHealthStatus.DEGRADED,
        responseTime,
        lastCheck: new Date(),
      };
    } catch (error) {
      return {
        name: 'redis',
        status: SystemHealthStatus.UNHEALTHY,
        responseTime: 0,
        lastCheck: new Date(),
        error: error.message,
      };
    }
  }

  private async checkStellarHealth(): Promise<any> {
    try {
      const start = Date.now();
      const responseTime = Date.now() - start;

      return {
        name: 'stellar',
        status: responseTime < 2000 ? SystemHealthStatus.HEALTHY : SystemHealthStatus.DEGRADED,
        responseTime,
        lastCheck: new Date(),
      };
    } catch (error) {
      return {
        name: 'stellar',
        status: SystemHealthStatus.UNHEALTHY,
        responseTime: 0,
        lastCheck: new Date(),
        error: error.message,
      };
    }
  }

  private async checkElasticsearchHealth(): Promise<any> {
    try {
      const start = Date.now();
      const responseTime = Date.now() - start;

      return {
        name: 'elasticsearch',
        status: responseTime < 1000 ? SystemHealthStatus.HEALTHY : SystemHealthStatus.DEGRADED,
        responseTime,
        lastCheck: new Date(),
      };
    } catch (error) {
      return {
        name: 'elasticsearch',
        status: SystemHealthStatus.UNHEALTHY,
        responseTime: 0,
        lastCheck: new Date(),
        error: error.message,
      };
    }
  }

  private async getSystemUptime(): Promise<number> {
    return process.uptime();
  }

  private async getMemoryUsage(): Promise<number> {
    const usage = process.memoryUsage();
    return usage.heapUsed / 1024 / 1024;
  }

  private async getCpuUsage(): Promise<number> {
    return process.cpuUsage().user / 1000000;
  }

  private async getDiskUsage(): Promise<number> {
    return 0;
  }

  private async getDatabaseConnections(): Promise<number> {
    try {
      const result = await this.dataSource.query('SELECT count(*) FROM pg_stat_activity');
      return parseInt(result[0].count);
    } catch {
      return 0;
    }
  }

  private async getCacheHitRate(): Promise<number> {
    const analytics = this.cache.getAnalytics();
    return analytics.totalRequests ? Math.round(analytics.hitRate * 1000) / 10 : 0;
  }

  private async getCacheEvictionRate(): Promise<number> {
    const analytics = this.cache.getAnalytics();
    return analytics.totalRequests ? Math.round(analytics.evictionRate * 1000) / 10 : 0;
  }
}
