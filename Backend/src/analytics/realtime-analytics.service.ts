import { Cron, CronExpression } from '@nestjs/schedule';
import { Injectable, Logger } from '@nestjs/common';

import { PrismaService } from '../prisma.service';
import { QueryRealtimeRollupsDto } from './dto/realtime-analytics.dto';
import { RealtimeAnalyticsGateway } from './realtime-analytics.gateway';

type RollupBucket = 'M1' | 'M5' | 'M15' | 'H1' | 'D1';
type AggregationMode = 'SUM' | 'AVG';

type LiveMetric = {
  name: string;
  value: number;
  aggregation: AggregationMode;
  dimensions?: Record<string, unknown>;
};

@Injectable()
export class RealtimeAnalyticsService {
  private readonly logger = new Logger(RealtimeAnalyticsService.name);

  private readonly rollupDurationsMs: Record<RollupBucket, number> = {
    M1: 60_000,
    M5: 5 * 60_000,
    M15: 15 * 60_000,
    H1: 60 * 60_000,
    D1: 24 * 60 * 60_000,
  };

  constructor(
    private readonly prisma: PrismaService,
    private readonly realtimeGateway: RealtimeAnalyticsGateway,
  ) {}

  @Cron(CronExpression.EVERY_MINUTE)
  async captureAndRollupMetrics(): Promise<void> {
    try {
      const now = new Date();
      const metrics = await this.collectLiveMetrics(now);

      for (const metric of metrics) {
        await (this.prisma as any).realtimeMetricSnapshot.create({
          data: {
            metricName: metric.name,
            metricValue: metric.value,
            dimensions: metric.dimensions || null,
            capturedAt: now,
          },
        });
      }

      const buckets: RollupBucket[] = ['M1', 'M5', 'M15', 'H1', 'D1'];
      for (const metric of metrics) {
        for (const bucket of buckets) {
          await this.upsertRollup(metric, bucket, now);
        }
      }

      const payload = {
        capturedAt: now.toISOString(),
        metrics: metrics.map((metric) => ({
          name: metric.name,
          value: metric.value,
          dimensions: metric.dimensions || {},
        })),
      };

      this.realtimeGateway.broadcastGlobal(payload);
      this.realtimeGateway.emitRollupRefresh({
        capturedAt: now.toISOString(),
        updatedMetrics: metrics.map((metric) => metric.name),
      });
    } catch (error) {
      this.logger.error(`Realtime analytics capture failed: ${error.message}`, error.stack);
    }
  }

  async getLiveMetrics(): Promise<Record<string, unknown>> {
    const snapshots = await (this.prisma as any).realtimeMetricSnapshot.findMany({
      orderBy: { capturedAt: 'desc' },
      take: 500,
    });

    const byMetric = new Map<string, any>();
    for (const snapshot of snapshots) {
      if (!byMetric.has(snapshot.metricName)) {
        byMetric.set(snapshot.metricName, snapshot);
      }
    }

    const metrics = Array.from(byMetric.entries()).map(([metricName, snapshot]) => ({
      metricName,
      metricValue: this.toNumber(snapshot.metricValue),
      dimensions: snapshot.dimensions || {},
      capturedAt: snapshot.capturedAt,
    }));

    return {
      capturedAt: new Date().toISOString(),
      metrics,
    };
  }

  async getRollups(query: QueryRealtimeRollupsDto): Promise<any[]> {
    const now = new Date();
    const from = query.from ? new Date(query.from) : new Date(now.getTime() - 24 * 60 * 60_000);
    const to = query.to ? new Date(query.to) : now;
    const limit = Math.max(1, Math.min(query.limit || 1000, 5000));

    const where: Record<string, unknown> = {
      bucketStart: { gte: from, lte: to },
    };
    if (query.metricName) {
      where.metricName = query.metricName;
    }
    if (query.bucket) {
      where.bucket = query.bucket;
    }

    const rows = await (this.prisma as any).realtimeMetricRollup.findMany({
      where,
      orderBy: [{ bucketStart: 'asc' }, { metricName: 'asc' }],
      take: limit,
    });

    return rows.map((row: any) => ({
      ...row,
      metricValue: this.toNumber(row.metricValue),
    }));
  }

  async getDashboardRange(from?: string, to?: string): Promise<Record<string, unknown>> {
    const now = new Date();
    const start = from ? new Date(from) : new Date(now.getTime() - 24 * 60 * 60_000);
    const end = to ? new Date(to) : now;

    const rows = await (this.prisma as any).realtimeMetricRollup.findMany({
      where: {
        bucket: 'M1',
        bucketStart: { gte: start, lte: end },
        metricName: {
          in: [
            'trading_volume',
            'trade_count',
            'active_users',
            'revenue_cents',
            'queue_backlog',
            'failed_transactions',
            'system_health_score',
          ],
        },
      },
      orderBy: { bucketStart: 'asc' },
    });

    const grouped = new Map<string, any[]>();
    for (const row of rows) {
      if (!grouped.has(row.metricName)) {
        grouped.set(row.metricName, []);
      }
      grouped.get(row.metricName)!.push({
        bucketStart: row.bucketStart,
        bucketEnd: row.bucketEnd,
        value: this.toNumber(row.metricValue),
      });
    }

    const volumeSeries = grouped.get('trading_volume') || [];
    const revenueSeries = grouped.get('revenue_cents') || [];
    const activeUsersSeries = grouped.get('active_users') || [];
    const healthSeries = grouped.get('system_health_score') || [];

    const totalTradingVolume = volumeSeries.reduce((sum, row) => sum + row.value, 0);
    const totalRevenueCents = revenueSeries.reduce((sum, row) => sum + row.value, 0);
    const avgHealthScore =
      healthSeries.length > 0
        ? healthSeries.reduce((sum, row) => sum + row.value, 0) / healthSeries.length
        : 0;
    const peakActiveUsers =
      activeUsersSeries.length > 0
        ? Math.max(...activeUsersSeries.map((row) => row.value))
        : 0;

    return {
      from: start.toISOString(),
      to: end.toISOString(),
      summary: {
        totalTradingVolume,
        totalRevenueCents,
        avgSystemHealthScore: Number(avgHealthScore.toFixed(2)),
        peakActiveUsers,
      },
      series: Object.fromEntries(grouped.entries()),
    };
  }

  async exportRollups(query: QueryRealtimeRollupsDto & { format?: 'csv' | 'excel' }): Promise<{
    format: 'csv' | 'excel';
    filename: string;
    contentType: string;
    content: string;
  }> {
    const rows = await this.getRollups(query);
    const format = query.format || 'csv';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    if (format === 'excel') {
      return {
        format,
        filename: `analytics-rollups-${timestamp}.xls`,
        contentType: 'application/vnd.ms-excel',
        content: this.toDelimited(rows, '\t'),
      };
    }

    return {
      format: 'csv',
      filename: `analytics-rollups-${timestamp}.csv`,
      contentType: 'text/csv',
      content: this.toDelimited(rows, ','),
    };
  }

  private async collectLiveMetrics(now: Date): Promise<LiveMetric[]> {
    const oneMinuteAgo = new Date(now.getTime() - 60_000);
    const fifteenMinutesAgo = new Date(now.getTime() - 15 * 60_000);

    const [tradeAggregate, tradeCount, activeUsersRaw, revenueAggregate, queuedCount, failedCount] =
      await Promise.all([
        (this.prisma as any).stakeLedger.aggregate({
          where: {
            createdAt: { gte: oneMinuteAgo, lte: now },
          },
          _sum: { amount: true },
        }),
        (this.prisma as any).stakeLedger.count({
          where: {
            createdAt: { gte: oneMinuteAgo, lte: now },
          },
        }),
        (this.prisma as any).analyticsEvent.findMany({
          where: {
            createdAt: { gte: fifteenMinutesAgo, lte: now },
            anonymized: false,
            userId: { not: null },
          },
          select: { userId: true },
          distinct: ['userId'],
        }),
        (this.prisma as any).invoice.aggregate({
          where: {
            status: 'PAID',
            paidAt: { gte: oneMinuteAgo, lte: now },
          },
          _sum: { amountPaid: true },
        }),
        (this.prisma as any).blockchainTransactionQueueItem.count({
          where: {
            status: { in: ['QUEUED', 'PROCESSING', 'SUBMITTED', 'STUCK'] },
          },
        }),
        (this.prisma as any).blockchainTransactionQueueItem.count({
          where: {
            status: { in: ['FAILED', 'DEAD_LETTER'] },
          },
        }),
      ]);

    const tradingVolume = this.toNumber(tradeAggregate?._sum?.amount);
    const revenueCents = this.toNumber(revenueAggregate?._sum?.amountPaid);
    const activeUsers = Array.isArray(activeUsersRaw) ? activeUsersRaw.length : 0;
    const queueBacklog = Number(queuedCount || 0);
    const failedTransactions = Number(failedCount || 0);

    const systemHealthScore = Math.max(
      0,
      Math.min(
        100,
        100 - Math.min(50, failedTransactions * 5) - Math.min(40, Math.floor(queueBacklog / 20)),
      ),
    );

    return [
      {
        name: 'trading_volume',
        value: tradingVolume,
        aggregation: 'SUM',
        dimensions: { unit: 'base_asset' },
      },
      {
        name: 'trade_count',
        value: Number(tradeCount || 0),
        aggregation: 'SUM',
      },
      {
        name: 'active_users',
        value: activeUsers,
        aggregation: 'AVG',
        dimensions: { window: '15m' },
      },
      {
        name: 'revenue_cents',
        value: revenueCents,
        aggregation: 'SUM',
      },
      {
        name: 'queue_backlog',
        value: queueBacklog,
        aggregation: 'AVG',
      },
      {
        name: 'failed_transactions',
        value: failedTransactions,
        aggregation: 'SUM',
      },
      {
        name: 'system_health_score',
        value: systemHealthScore,
        aggregation: 'AVG',
      },
    ];
  }

  private async upsertRollup(
    metric: LiveMetric,
    bucket: RollupBucket,
    referenceTime: Date,
  ): Promise<void> {
    const bucketStart = this.getBucketStart(referenceTime, bucket);
    const bucketEnd = new Date(bucketStart.getTime() + this.rollupDurationsMs[bucket]);

    const snapshots = await (this.prisma as any).realtimeMetricSnapshot.findMany({
      where: {
        metricName: metric.name,
        capturedAt: { gte: bucketStart, lt: bucketEnd },
      },
      orderBy: { capturedAt: 'asc' },
      select: {
        metricValue: true,
      },
    });

    if (snapshots.length === 0) {
      return;
    }

    const values = snapshots.map((snapshot: any) => this.toNumber(snapshot.metricValue));
    const computedValue =
      metric.aggregation === 'SUM'
        ? values.reduce((sum, value) => sum + value, 0)
        : values.reduce((sum, value) => sum + value, 0) / values.length;

    const existing = await (this.prisma as any).realtimeMetricRollup.findFirst({
      where: {
        bucket,
        metricName: metric.name,
        bucketStart,
      },
    });

    if (existing) {
      await (this.prisma as any).realtimeMetricRollup.update({
        where: { id: existing.id },
        data: {
          metricValue: computedValue,
          bucketEnd,
          dimensions: metric.dimensions || null,
        },
      });
      return;
    }

    await (this.prisma as any).realtimeMetricRollup.create({
      data: {
        bucket,
        metricName: metric.name,
        metricValue: computedValue,
        dimensions: metric.dimensions || null,
        bucketStart,
        bucketEnd,
      },
    });
  }

  private getBucketStart(date: Date, bucket: RollupBucket): Date {
    const base = new Date(date);
    base.setSeconds(0, 0);

    if (bucket === 'M1') {
      return base;
    }

    if (bucket === 'M5') {
      base.setMinutes(Math.floor(base.getMinutes() / 5) * 5);
      return base;
    }

    if (bucket === 'M15') {
      base.setMinutes(Math.floor(base.getMinutes() / 15) * 15);
      return base;
    }

    if (bucket === 'H1') {
      base.setMinutes(0);
      return base;
    }

    base.setHours(0, 0, 0, 0);
    return base;
  }

  private toDelimited(rows: any[], delimiter: ',' | '\t'): string {
    const headers = [
      'bucket',
      'metricName',
      'metricValue',
      'bucketStart',
      'bucketEnd',
      'dimensions',
      'createdAt',
    ];

    const quote = (value: unknown): string => {
      if (value === null || value === undefined) {
        return '';
      }
      const asString =
        typeof value === 'object' ? JSON.stringify(value) : String(value).replace(/\r?\n/g, ' ');
      const escaped = asString.replace(/"/g, '""');
      return `"${escaped}"`;
    };

    const lines = [headers.join(delimiter)];
    for (const row of rows) {
      lines.push(
        [
          row.bucket,
          row.metricName,
          row.metricValue,
          row.bucketStart,
          row.bucketEnd,
          row.dimensions || {},
          row.createdAt,
        ]
          .map((value) => quote(value))
          .join(delimiter),
      );
    }

    return lines.join('\n');
  }

  private toNumber(value: unknown): number {
    if (value === null || value === undefined) {
      return 0;
    }

    if (typeof value === 'number') {
      return Number.isFinite(value) ? value : 0;
    }

    if (typeof value === 'bigint') {
      return Number(value);
    }

    if (typeof value === 'string') {
      const parsed = Number.parseFloat(value);
      return Number.isFinite(parsed) ? parsed : 0;
    }

    if (typeof value === 'object' && value !== null) {
      if ('toNumber' in (value as Record<string, unknown>)) {
        const asAny = value as any;
        const converted = asAny.toNumber();
        return Number.isFinite(converted) ? converted : 0;
      }
      if ('toString' in (value as Record<string, unknown>)) {
        const parsed = Number.parseFloat((value as any).toString());
        return Number.isFinite(parsed) ? parsed : 0;
      }
    }

    return 0;
  }
}

