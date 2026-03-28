import { Injectable, ConflictException, NotFoundException, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { NotificationService } from '../notification/services/notification.service';
import { AdvancedCacheService } from '../cache/advanced-cache.service';
import { EventBusService } from '../messaging/rabbitmq/event-bus.service';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantSettingsDto } from './dto/update-tenant-settings.dto';
import { ApiOveragePolicy, TenantPlan, NotificationType } from '@prisma/client';

const PLAN_DEFAULTS: Record<
  TenantPlan,
  {
    maxUsers: number;
    maxProjects: number;
    apiCallsPerMonthLimit: number;
    storageGbLimit: number;
    apiOveragePolicy: ApiOveragePolicy;
  }
> = {
  FREE: {
    maxUsers: 10,
    maxProjects: 5,
    apiCallsPerMonthLimit: 100000,
    storageGbLimit: 100,
    apiOveragePolicy: 'HARD_STOP',
  },
  STARTER: {
    maxUsers: 50,
    maxProjects: 20,
    apiCallsPerMonthLimit: 500000,
    storageGbLimit: 500,
    apiOveragePolicy: 'HARD_STOP',
  },
  PROFESSIONAL: {
    maxUsers: 200,
    maxProjects: 100,
    apiCallsPerMonthLimit: 2000000,
    storageGbLimit: 2000,
    apiOveragePolicy: 'HARD_STOP',
  },
  ENTERPRISE: {
    maxUsers: 500,
    maxProjects: 500,
    apiCallsPerMonthLimit: 10000000,
    storageGbLimit: 10000,
    apiOveragePolicy: 'BILL_OVERAGE',
  },
};

@Injectable()
export class TenantService {
  private readonly logger = new Logger(TenantService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly notificationService: NotificationService,
    private readonly cache: AdvancedCacheService,
    private readonly eventBus: EventBusService,
  ) {}

  async provision(dto: CreateTenantDto, actorId?: string) {
    const slug = this.toSlug(dto.name);
    const plan = dto.plan ?? TenantPlan.FREE;
    const planDefaults = PLAN_DEFAULTS[plan];

    // Uniqueness guard
    const existing = await this.prisma.tenant.findFirst({
      where: { OR: [{ name: dto.name }, { slug }] },
    });
    if (existing) {
      throw new ConflictException(`A tenant with name "${dto.name}" already exists`);
    }

    const existingAdmin = await this.prisma.user.findUnique({
      where: { walletAddress: dto.adminWalletAddress },
    });
    if (existingAdmin) {
      throw new ConflictException(
        `Wallet address "${dto.adminWalletAddress}" is already registered`,
      );
    }

    // Atomic provisioning inside a transaction
    const { tenant, adminUser } = await this.prisma.$transaction(async (tx) => {
      const tenant = await tx.tenant.create({
        data: {
          name: dto.name,
          slug,
          plan,
          status: 'ACTIVE',
        },
      });

      await tx.tenantSettings.create({
        data: {
          tenantId: tenant.id,
          maxUsers: dto.settings?.maxUsers ?? planDefaults.maxUsers,
          maxProjects: dto.settings?.maxProjects ?? planDefaults.maxProjects,
          apiCallsPerMonthLimit:
            dto.settings?.apiCallsPerMonthLimit ?? planDefaults.apiCallsPerMonthLimit,
          storageGbLimit: dto.settings?.storageGbLimit ?? planDefaults.storageGbLimit,
          apiOveragePolicy: dto.settings?.apiOveragePolicy ?? planDefaults.apiOveragePolicy,
          allowPublicProjects: dto.settings?.allowPublicProjects ?? true,
          notificationsEnabled: dto.settings?.notificationsEnabled ?? true,
        },
      });

      const adminUser = await tx.user.create({
        data: {
          walletAddress: dto.adminWalletAddress,
          email: dto.adminEmail,
          roles: ['TENANT_ADMIN'],
          tenantId: tenant.id,
        },
      });

      await tx.tenantAuditLog.create({
        data: {
          tenantId: tenant.id,
          action: 'TENANT_PROVISIONED',
          actorId: actorId ?? null,
          metadata: {
            plan,
            adminWalletAddress: dto.adminWalletAddress,
            slug,
          },
        },
      });

      return { tenant, adminUser };
    });

    // Dispatch welcome notification — non-blocking
    if (dto.adminEmail) {
      this.dispatchWelcomeNotification(adminUser.id, dto.name).catch((err) =>
        this.logger.error(`Welcome notification failed for tenant ${tenant.id}: ${err.message}`),
      );
    }

    // Publish domain event for loose-coupled downstream processing.
    this.eventBus
      .publish('UserCreated', {
        userId: adminUser.id,
        tenantId: tenant.id,
        walletAddress: adminUser.walletAddress,
        roles: adminUser.roles,
      })
      .catch((err) =>
        this.logger.warn(
          `Failed to publish UserCreated event for tenant ${tenant.id}: ${err.message}`,
        ),
      );

    this.logger.log(`Tenant provisioned: ${tenant.id} (${tenant.slug})`);

    return {
      tenant: {
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug,
        plan: tenant.plan,
        status: tenant.status,
        createdAt: tenant.createdAt,
      },
      adminUser: {
        id: adminUser.id,
        walletAddress: adminUser.walletAddress,
        roles: adminUser.roles,
      },
    };
  }

  async findAll() {
    return this.prisma.tenant.findMany({
      where: { status: { not: 'DELETED' } },
      include: { settings: true, _count: { select: { users: true } } },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findOne(id: string) {
    const tenant = await this.prisma.tenant.findUnique({
      where: { id },
      include: { settings: true, _count: { select: { users: true, auditLogs: true } } },
    });
    if (!tenant) throw new NotFoundException(`Tenant ${id} not found`);
    return tenant;
  }

  async getSettings(tenantId: string) {
    const cacheTag = `tenant-settings:${tenantId}`;
    const cacheKey = `tenantSettings:${tenantId}`;

    const toApiShape = (s: any) => ({
      ...s,
      // Normalize Date objects so JSON-cached values have stable shape.
      createdAt: s.createdAt ? (s.createdAt.toISOString?.() ?? s.createdAt) : null,
      updatedAt: s.updatedAt ? (s.updatedAt.toISOString?.() ?? s.updatedAt) : null,
    });

    return this.cache.getOrSet(
      cacheKey,
      async () => {
        const settings = await this.prisma.tenantSettings.findUnique({
          where: { tenantId },
        });
        if (!settings) throw new NotFoundException(`Settings for tenant ${tenantId} not found`);
        return toApiShape(settings);
      },
      { ttlSeconds: 300 },
      [cacheTag],
    );
  }

  async updateSettings(tenantId: string, dto: UpdateTenantSettingsDto, actorId?: string) {
    await this.findOne(tenantId);

    const updated = await this.prisma.tenantSettings.update({
      where: { tenantId },
      data: dto,
    });

    await this.prisma.tenantAuditLog.create({
      data: {
        tenantId,
        action: 'SETTINGS_UPDATED',
        actorId: actorId ?? null,
        metadata: dto as object,
      },
    });

    // Tag-based invalidation so subsequent reads go to DB (cache-aside).
    await this.cache.invalidateTags([`tenant-settings:${tenantId}`]);

    return updated;
  }

  async getAuditLogs(tenantId: string) {
    await this.findOne(tenantId);
    return this.prisma.tenantAuditLog.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
  }

  private toSlug(name: string): string {
    return name
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  private async dispatchWelcomeNotification(userId: string, tenantName: string) {
    await this.notificationService.notify(
      userId,
      NotificationType.SYSTEM,
      'Welcome to Stellara',
      `Your tenant "${tenantName}" has been successfully provisioned. You can now log in using your wallet address.`,
      { event: 'TENANT_PROVISIONED', tenantName },
    );
  }
}
