import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

export interface TrackEventDto {
  userId: string;
  eventType: 'PAGE_VIEW' | 'CLICK' | 'FORM_SUBMISSION' | 'FEATURE_USAGE' | 'CUSTOM';
  eventName: string;
  properties?: Record<string, any>;
  sessionId?: string;
  anonymized?: boolean;
}

export interface FunnelStep {
  step: string;
  count: number;
  dropoffRate: number;
}

export interface CohortRetention {
  cohortDate: string;
  d1: number;
  d7: number;
  d30: number;
  cohortSize: number;
}

export interface HeatmapData {
  page: string;
  clicks: Array<{ x: number; y: number; count: number }>;
}

@Injectable()
export class BehavioralAnalyticsService {
  private readonly logger = new Logger(BehavioralAnalyticsService.name);

  constructor(private readonly prisma: PrismaService) {}

  async trackEvent(dto: TrackEventDto): Promise<{ id: string }> {
    // Check if user has opted out
    const optOut = await this.prisma.analyticsOptOut.findUnique({
      where: { userId: dto.userId },
    });

    if (optOut) {
      this.logger.debug(`User ${dto.userId} has opted out of tracking. Skipping event.`);
      return { id: '' };
    }

    const event = await this.prisma.analyticsEvent.create({
      data: {
        userId: dto.anonymized ? null : dto.userId,
        sessionId: dto.sessionId,
        eventType: dto.eventType,
        eventName: dto.eventName,
        properties: dto.properties ?? {},
        anonymized: dto.anonymized ?? false,
      },
    });

    // Push to third-party integrations (fire-and-forget)
    this.pushToMixpanel(dto).catch((err) =>
      this.logger.warn(`Mixpanel push failed: ${err.message}`),
    );
    this.pushToAmplitude(dto).catch((err) =>
      this.logger.warn(`Amplitude push failed: ${err.message}`),
    );

    return { id: event.id };
  }

  async getFunnelAnalysis(funnelName: string): Promise<FunnelStep[]> {
    // Supported funnels
    const funnelSteps: Record<string, string[]> = {
      'registration→deposit→trade': ['REGISTRATION_STARTED', 'DEPOSIT_INITIATED', 'TRADE_EXECUTED'],
      'onboarding': ['SIGNUP', 'KYC_STARTED', 'KYC_COMPLETED', 'FIRST_DEPOSIT'],
    };

    const steps = funnelSteps[funnelName] ?? ['REGISTRATION_STARTED', 'DEPOSIT_INITIATED', 'TRADE_EXECUTED'];

    const stepCounts = await Promise.all(
      steps.map((step) =>
        this.prisma.analyticsEvent.count({
          where: { eventName: step, anonymized: false },
        }),
      ),
    );

    const result: FunnelStep[] = [];
    for (let i = 0; i < steps.length; i++) {
      const count = stepCounts[i];
      const previousCount = i === 0 ? count : stepCounts[i - 1];
      const dropoffRate = previousCount === 0 ? 0 : ((previousCount - count) / previousCount) * 100;
      result.push({ step: steps[i], count, dropoffRate: Math.round(dropoffRate * 100) / 100 });
    }

    return result;
  }

  async getCohortRetention(cohortDate: Date): Promise<CohortRetention> {
    const cohortStart = new Date(cohortDate);
    cohortStart.setHours(0, 0, 0, 0);
    const cohortEnd = new Date(cohortStart);
    cohortEnd.setDate(cohortEnd.getDate() + 1);

    // Get users who first appeared in the cohort day
    const cohortUsers = await this.prisma.analyticsEvent.findMany({
      where: {
        createdAt: { gte: cohortStart, lt: cohortEnd },
        anonymized: false,
        userId: { not: null },
      },
      select: { userId: true },
      distinct: ['userId'],
    });

    const cohortUserIds = cohortUsers.map((u) => u.userId).filter(Boolean) as string[];
    const cohortSize = cohortUserIds.length;

    if (cohortSize === 0) {
      return {
        cohortDate: cohortStart.toISOString().split('T')[0],
        d1: 0,
        d7: 0,
        d30: 0,
        cohortSize: 0,
      };
    }

    const countRetained = async (daysAfter: number): Promise<number> => {
      const start = new Date(cohortStart);
      start.setDate(start.getDate() + daysAfter);
      const end = new Date(start);
      end.setDate(end.getDate() + 1);

      const retained = await this.prisma.analyticsEvent.findMany({
        where: {
          userId: { in: cohortUserIds },
          createdAt: { gte: start, lt: end },
          anonymized: false,
        },
        select: { userId: true },
        distinct: ['userId'],
      });

      return retained.length;
    };

    const [d1Count, d7Count, d30Count] = await Promise.all([
      countRetained(1),
      countRetained(7),
      countRetained(30),
    ]);

    return {
      cohortDate: cohortStart.toISOString().split('T')[0],
      d1: Math.round((d1Count / cohortSize) * 10000) / 100,
      d7: Math.round((d7Count / cohortSize) * 10000) / 100,
      d30: Math.round((d30Count / cohortSize) * 10000) / 100,
      cohortSize,
    };
  }

  async getHeatmapData(page: string): Promise<HeatmapData> {
    const events = await this.prisma.analyticsEvent.findMany({
      where: {
        page,
        eventType: 'CLICK',
        anonymized: false,
      },
      select: { properties: true },
    });

    const clickMap = new Map<string, { x: number; y: number; count: number }>();

    for (const event of events) {
      const props = event.properties as Record<string, any> | null;
      if (!props || typeof props.x !== 'number' || typeof props.y !== 'number') {
        continue;
      }

      // Bucket coordinates to nearest 10px for aggregation
      const bx = Math.round(props.x / 10) * 10;
      const by = Math.round(props.y / 10) * 10;
      const key = `${bx}:${by}`;

      if (clickMap.has(key)) {
        clickMap.get(key)!.count += 1;
      } else {
        clickMap.set(key, { x: bx, y: by, count: 1 });
      }
    }

    return {
      page,
      clicks: Array.from(clickMap.values()).sort((a, b) => b.count - a.count),
    };
  }

  async optOut(userId: string): Promise<{ success: boolean }> {
    await this.prisma.analyticsOptOut.upsert({
      where: { userId },
      update: { optedOutAt: new Date() },
      create: { userId },
    });

    this.logger.log(`User ${userId} has opted out of behavioral analytics tracking.`);
    return { success: true };
  }

  async anonymizeUser(userId: string): Promise<{ anonymized: number }> {
    const result = await this.prisma.analyticsEvent.updateMany({
      where: { userId },
      data: {
        userId: null,
        anonymized: true,
        properties: {},
        sessionId: null,
      },
    });

    this.logger.log(`Anonymized ${result.count} events for user ${userId}.`);
    return { anonymized: result.count };
  }

  async pushToMixpanel(event: TrackEventDto): Promise<void> {
    const token = process.env.MIXPANEL_TOKEN;
    if (!token) {
      this.logger.debug('MIXPANEL_TOKEN not configured, skipping Mixpanel push.');
      return;
    }

    // Real integration would POST to https://api.mixpanel.com/track
    this.logger.debug(
      `[Mixpanel] Pushing event "${event.eventName}" for user ${event.userId} (type: ${event.eventType})`,
    );
    // Stub: log only. Replace with actual Mixpanel HTTP call using axios when token is configured.
  }

  async pushToAmplitude(event: TrackEventDto): Promise<void> {
    const apiKey = process.env.AMPLITUDE_API_KEY;
    if (!apiKey) {
      this.logger.debug('AMPLITUDE_API_KEY not configured, skipping Amplitude push.');
      return;
    }

    // Real integration would POST to https://api2.amplitude.com/2/httpapi
    this.logger.debug(
      `[Amplitude] Pushing event "${event.eventName}" for user ${event.userId} (type: ${event.eventType})`,
    );
    // Stub: log only. Replace with actual Amplitude HTTP call using axios when apiKey is configured.
  }
}
