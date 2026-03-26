import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { BucketerService } from './bucketer.service';
import { StatisticsEngineService, ExperimentStats } from './engine.service';
import { Experiment, ExperimentStatus, ExperimentVariant, Prisma } from '@prisma/client';

@Injectable()
export class ExperimentsService implements OnModuleInit {
  private readonly logger = new Logger(ExperimentsService.name);
  private experimentsCache = new Map<string, Experiment>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly bucketer: BucketerService,
    private readonly statsEngine: StatisticsEngineService,
  ) {}

  async onModuleInit() {
    await this.refreshCache();
  }

  async refreshCache() {
    const experiments = await this.prisma.experiment.findMany({
      where: { status: 'ACTIVE' },
    });
    this.experimentsCache.clear();
    for (const exp of experiments) {
      this.experimentsCache.set(exp.key, exp);
    }
  }

  async getAssignment(userId: string, experimentKey: string): Promise<ExperimentVariant | null> {
    let experiment = this.experimentsCache.get(experimentKey);
    
    if (!experiment) {
      experiment = await this.prisma.experiment.findUnique({
        where: { key: experimentKey },
      });
      if (!experiment || experiment.status !== 'ACTIVE') return null;
    }

    if (!this.bucketer.isInRollout(experiment.key, userId, experiment.trafficCoverage)) {
      return null;
    }

    const variant = this.bucketer.getVariant(experiment.key, userId, experiment.controlSize);

    this.persistAssignment(experiment.id, userId, variant as ExperimentVariant).catch(err => {
      this.logger.error(`Failed to persist experiment assignment for user ${userId}`, err);
    });

    return variant as ExperimentVariant;
  }

  private async persistAssignment(experimentId: string, userId: string, variant: ExperimentVariant) {
    await this.prisma.experimentAssignment.upsert({
      where: {
        experimentId_userId: { experimentId, userId },
      },
      update: { variant },
      create: { experimentId, userId, variant },
    });
  }

  async trackEvent(userId: string, experimentKey: string, eventName: string, value?: number) {
    const experiment = await this.prisma.experiment.findUnique({
      where: { key: experimentKey },
    });

    if (!experiment || experiment.status !== 'ACTIVE') return;

    await this.prisma.experimentEvent.create({
      data: {
        experimentId: experiment.id,
        userId,
        eventName,
        value: value ?? 1.0,
      },
    });
  }

  /**
   * Retrieves results and statistical analysis for an experiment, including segment analysis.
   */
  async getDetailedAnalysis(experimentKey: string) {
    const experiment = await (this.prisma as any).experiment.findUnique({
      where: { key: experimentKey },
      include: {
        assignments: {
          include: { user: true },
        },
        events: true,
      },
    });

    if (!experiment) return null;

    const conversionEvents = experiment.events.filter((e: any) => e.eventName === experiment.metricName);
    const convertedUserIds = new Set<string>(conversionEvents.map((e: any) => e.userId));

    // Global Stats
    const globalStats = this.aggregateStats(experiment.assignments, convertedUserIds);
    const globalAnalysis = this.statsEngine.calculateSignificance(globalStats);

    // Segment Analysis: New vs Existing Users (arbitrary threshold: 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const newUsersAssignments = experiment.assignments.filter((a: any) => a.user.createdAt > thirtyDaysAgo);
    const existingUsersAssignments = experiment.assignments.filter((a: any) => a.user.createdAt <= thirtyDaysAgo);

    const newUsersStats = this.aggregateStats(newUsersAssignments, convertedUserIds);
    const existingUsersStats = this.aggregateStats(existingUsersAssignments, convertedUserIds);

    // Early stopping logic
    const minSampleSize = 100;
    const earlyStoppingAvailable = 
      globalStats.controlCount > minSampleSize && 
      globalStats.treatmentCount > minSampleSize && 
      globalAnalysis.pValue < 0.001;

    return {
      global: globalAnalysis,
      segments: {
        newUsers: this.statsEngine.calculateSignificance(newUsersStats),
        existingUsers: this.statsEngine.calculateSignificance(existingUsersStats),
      },
      earlyStoppingRecommended: earlyStoppingAvailable,
      metadata: experiment.metadata,
      sampleSize: globalStats.controlCount + globalStats.treatmentCount,
    };
  }

  private aggregateStats(assignments: any[], convertedUserIds: Set<string>): ExperimentStats {
    const control = assignments.filter(a => a.variant === 'CONTROL');
    const treatment = assignments.filter(a => a.variant === 'TREATMENT');

    return {
      controlCount: control.length,
      controlConversions: control.filter(a => convertedUserIds.has(a.userId)).length,
      treatmentCount: treatment.length,
      treatmentConversions: treatment.filter(a => convertedUserIds.has(a.userId)).length,
    };
  }

  async createExperiment(data: Prisma.ExperimentCreateInput) {
    const experiment = await (this.prisma as any).experiment.create({ data });
    await this.refreshCache();
    return experiment;
  }

  async setExperimentStatus(key: string, status: ExperimentStatus) {
    await (this.prisma as any).experiment.update({
      where: { key },
      data: { status },
    });
    await this.refreshCache();
  }
}
