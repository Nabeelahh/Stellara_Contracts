import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { ConfigAuditService } from './config-audit.service';
import { ConfigScope, FeatureFlagEntry } from '../interfaces/config.interfaces';
import { SetFeatureFlagDto } from '../dto/config.dto';

@Injectable()
export class FeatureFlagService {
  private readonly logger = new Logger(FeatureFlagService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: ConfigAuditService,
  ) {}

  /**
   * Check if a feature flag is enabled for a given tenant/user.
   * Tenant-level flag overrides global; rollout percentage is applied.
   */
  async isEnabled(key: string, tenantId?: string, userId?: string): Promise<boolean> {
    // Tenant-specific flag takes precedence
    if (tenantId) {
      const tenantFlag = await (this.prisma as any).featureFlag.findUnique({
        where: { key_tenantId: { key, tenantId } },
      });
      if (tenantFlag) return this.applyRollout(tenantFlag, userId);
    }

    // Fall back to global flag
    const globalFlag = await (this.prisma as any).featureFlag.findFirst({
      where: { key, tenantId: null },
    });
    if (globalFlag) return this.applyRollout(globalFlag, userId);

    return false;
  }

  async setFlag(dto: SetFeatureFlagDto, actorId?: string): Promise<FeatureFlagEntry> {
    const existing = await (this.prisma as any).featureFlag.findFirst({
      where: { key: dto.key, tenantId: dto.tenantId ?? null },
    });

    const data = {
      key: dto.key,
      enabled: dto.enabled,
      tenantId: dto.tenantId ?? null,
      rolloutPct: dto.rolloutPct ?? 100,
      metadata: dto.metadata ?? undefined,
    };

    const flag = existing
      ? await (this.prisma as any).featureFlag.update({ where: { id: existing.id }, data })
      : await (this.prisma as any).featureFlag.create({ data });

    await this.audit.log({
      key: `feature:${dto.key}`,
      oldValue: existing ? String(existing.enabled) : undefined,
      newValue: String(dto.enabled),
      scope: dto.tenantId ? ConfigScope.TENANT : ConfigScope.GLOBAL,
      tenantId: dto.tenantId,
      actorId,
      action: 'SET',
    });

    return flag;
  }

  async listFlags(tenantId?: string): Promise<FeatureFlagEntry[]> {
    return (this.prisma as any).featureFlag.findMany({
      where: tenantId ? { OR: [{ tenantId }, { tenantId: null }] } : { tenantId: null },
      orderBy: { key: 'asc' },
    });
  }

  async deleteFlag(key: string, tenantId?: string, actorId?: string): Promise<void> {
    const flag = await (this.prisma as any).featureFlag.findFirst({
      where: { key, tenantId: tenantId ?? null },
    });
    if (!flag) return;

    await (this.prisma as any).featureFlag.delete({ where: { id: flag.id } });
    await this.audit.log({
      key: `feature:${key}`,
      oldValue: String(flag.enabled),
      scope: tenantId ? ConfigScope.TENANT : ConfigScope.GLOBAL,
      tenantId,
      actorId,
      action: 'DELETE',
    });
  }

  private applyRollout(flag: { enabled: boolean; rolloutPct: number }, userId?: string): boolean {
    if (!flag.enabled) return false;
    if (flag.rolloutPct >= 100) return true;
    if (flag.rolloutPct <= 0) return false;

    // Deterministic hash-based rollout using userId
    const seed = userId ?? Math.random().toString();
    const hash = seed.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
    return hash % 100 < flag.rolloutPct;
  }
}
