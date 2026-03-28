import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma.service';
import { SyntheticTestResultDto } from './monitoring.dto';
import axios from 'axios';
import { CircuitBreakerService } from '../circuit-breaker/circuit-breaker.service';

const LOCATIONS = ['us-east', 'eu-west', 'ap-southeast', 'us-west', 'sa-east'];

const BASE_URL = process.env.INTERNAL_BASE_URL ?? 'http://localhost:3000';

const SLA_TARGET_UPTIME = 99.9; // percent
const ALERT_ERROR_RATE_THRESHOLD = 1; // percent
const ALERT_P95_LATENCY_THRESHOLD = 2000; // ms

@Injectable()
export class MonitoringService {
  private readonly logger = new Logger(MonitoringService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly circuitBreakerService: CircuitBreakerService,
  ) {
    this.circuitBreakerService.register('internal-synthetic-http', {
      failureThreshold: 5,
      failureWindowMs: 10_000,
      openTimeoutMs: 30_000,
      halfOpenMaxCalls: 10,
      halfOpenSuccessThreshold: 3,
    });
  }

  @Cron(CronExpression.EVERY_5_MINUTES)
  async runSyntheticTests(): Promise<void> {
    this.logger.log('Starting synthetic test run across all locations...');

    const journeys = [
      { name: 'login', fn: (loc: string) => this.runLoginJourney(loc) },
      { name: 'deposit', fn: (loc: string) => this.runDepositJourney(loc) },
      { name: 'trade', fn: (loc: string) => this.runTradeJourney(loc) },
      { name: 'withdrawal', fn: (loc: string) => this.runWithdrawalJourney(loc) },
    ];

    const tasks: Promise<void>[] = [];

    for (const location of LOCATIONS) {
      for (const journey of journeys) {
        const task = (async () => {
          const start = Date.now();
          try {
            const result = await journey.fn(location);
            await this.recordResult({
              testName: journey.name,
              location,
              durationMs: result.durationMs,
              success: result.success,
              errorMessage: result.error,
              statusCode: result.statusCode,
            });
          } catch (err: any) {
            await this.recordResult({
              testName: journey.name,
              location,
              durationMs: Date.now() - start,
              success: false,
              errorMessage: err.message ?? 'Unknown error',
            });
          }
        })();
        tasks.push(task);
      }
    }

    await Promise.allSettled(tasks);
    await this.checkAlerts();
    this.logger.log('Synthetic test run completed.');
  }

  async runLoginJourney(location: string): Promise<{ success: boolean; durationMs: number; error?: string; statusCode?: number }> {
    const start = Date.now();
    try {
      const response = await this.postWithCircuit(
        `${BASE_URL}/auth/login`,
        { walletAddress: 'synthetic-test-wallet', signature: 'synthetic-sig' },
        { timeout: 10000, headers: { 'X-Synthetic-Test': 'true', 'X-Location': location } },
      );
      return { success: response.status < 400, durationMs: Date.now() - start, statusCode: response.status };
    } catch (err: any) {
      const status = err.response?.status;
      // 401 Unauthorized is expected for synthetic credentials - treat as success for latency testing
      if (status === 401 || status === 400) {
        return { success: true, durationMs: Date.now() - start, statusCode: status };
      }
      return {
        success: false,
        durationMs: Date.now() - start,
        error: err.message,
        statusCode: status,
      };
    }
  }

  async runDepositJourney(location: string): Promise<{ success: boolean; durationMs: number; error?: string; statusCode?: number }> {
    const start = Date.now();
    try {
      const response = await this.postWithCircuit(
        `${BASE_URL}/payment/deposit`,
        { amount: 0.001, currency: 'XLM', synthetic: true },
        { timeout: 10000, headers: { 'X-Synthetic-Test': 'true', 'X-Location': location } },
      );
      return { success: response.status < 500, durationMs: Date.now() - start, statusCode: response.status };
    } catch (err: any) {
      const status = err.response?.status;
      if (status && status < 500) {
        return { success: true, durationMs: Date.now() - start, statusCode: status };
      }
      return {
        success: false,
        durationMs: Date.now() - start,
        error: err.message,
        statusCode: status,
      };
    }
  }

  async runTradeJourney(location: string): Promise<{ success: boolean; durationMs: number; error?: string; statusCode?: number }> {
    const start = Date.now();
    try {
      const response = await this.postWithCircuit(
        `${BASE_URL}/trade`,
        { pair: 'XLM/USDC', amount: 0.001, side: 'buy', synthetic: true },
        { timeout: 10000, headers: { 'X-Synthetic-Test': 'true', 'X-Location': location } },
      );
      return { success: response.status < 500, durationMs: Date.now() - start, statusCode: response.status };
    } catch (err: any) {
      const status = err.response?.status;
      if (status && status < 500) {
        return { success: true, durationMs: Date.now() - start, statusCode: status };
      }
      return {
        success: false,
        durationMs: Date.now() - start,
        error: err.message,
        statusCode: status,
      };
    }
  }

  async runWithdrawalJourney(location: string): Promise<{ success: boolean; durationMs: number; error?: string; statusCode?: number }> {
    const start = Date.now();
    try {
      const response = await this.postWithCircuit(
        `${BASE_URL}/payment/withdraw`,
        { amount: 0.001, currency: 'XLM', destinationAddress: 'synthetic-dest', synthetic: true },
        { timeout: 10000, headers: { 'X-Synthetic-Test': 'true', 'X-Location': location } },
      );
      return { success: response.status < 500, durationMs: Date.now() - start, statusCode: response.status };
    } catch (err: any) {
      const status = err.response?.status;
      if (status && status < 500) {
        return { success: true, durationMs: Date.now() - start, statusCode: status };
      }
      return {
        success: false,
        durationMs: Date.now() - start,
        error: err.message,
        statusCode: status,
      };
    }
  }

  async recordResult(result: SyntheticTestResultDto): Promise<void> {
    await this.prisma.syntheticTestResult.create({
      data: {
        testName: result.testName,
        location: result.location,
        durationMs: result.durationMs,
        success: result.success,
        errorMessage: result.errorMessage ?? null,
        statusCode: result.statusCode ?? null,
      },
    });
  }

  async getLatencyPercentiles(
    testName: string,
    hours = 24,
  ): Promise<{ p50: number; p95: number; p99: number; count: number; testName: string; hours: number }> {
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    const results = await this.prisma.syntheticTestResult.findMany({
      where: { testName, createdAt: { gte: since }, success: true },
      select: { durationMs: true },
      orderBy: { durationMs: 'asc' },
    });

    if (results.length === 0) {
      return { p50: 0, p95: 0, p99: 0, count: 0, testName, hours };
    }

    const durations = results.map((r) => r.durationMs).sort((a, b) => a - b);
    const count = durations.length;

    const percentile = (p: number): number => {
      const idx = Math.ceil((p / 100) * count) - 1;
      return durations[Math.max(0, Math.min(idx, count - 1))];
    };

    return {
      p50: percentile(50),
      p95: percentile(95),
      p99: percentile(99),
      count,
      testName,
      hours,
    };
  }

  async checkAlerts(): Promise<void> {
    const journeyNames = ['login', 'deposit', 'trade', 'withdrawal'];
    const windowMs = 5 * 60 * 1000; // last 5 minutes
    const since = new Date(Date.now() - windowMs);

    for (const testName of journeyNames) {
      const [total, failures] = await Promise.all([
        this.prisma.syntheticTestResult.count({
          where: { testName, createdAt: { gte: since } },
        }),
        this.prisma.syntheticTestResult.count({
          where: { testName, createdAt: { gte: since }, success: false },
        }),
      ]);

      if (total === 0) continue;

      const errorRate = (failures / total) * 100;
      if (errorRate > ALERT_ERROR_RATE_THRESHOLD) {
        this.logger.error(
          `ALERT [${testName}]: Error rate ${errorRate.toFixed(2)}% exceeds threshold ${ALERT_ERROR_RATE_THRESHOLD}% in last 5 minutes. Failures: ${failures}/${total}`,
        );
      }

      const { p95 } = await this.getLatencyPercentiles(testName, 0.083); // ~5 min
      if (p95 > ALERT_P95_LATENCY_THRESHOLD) {
        this.logger.error(
          `ALERT [${testName}]: P95 latency ${p95}ms exceeds threshold ${ALERT_P95_LATENCY_THRESHOLD}ms.`,
        );
      }
    }
  }

  async getSlaReport(
    startDate: Date,
    endDate: Date,
  ): Promise<{
    startDate: Date;
    endDate: Date;
    uptimePercentage: number;
    targetUptime: number;
    totalTests: number;
    failures: number;
    slaBreached: boolean;
    byJourney: Array<{ testName: string; total: number; failures: number; uptime: number }>;
  }> {
    const [totalTests, failures] = await Promise.all([
      this.prisma.syntheticTestResult.count({
        where: { createdAt: { gte: startDate, lte: endDate } },
      }),
      this.prisma.syntheticTestResult.count({
        where: { createdAt: { gte: startDate, lte: endDate }, success: false },
      }),
    ]);

    const uptimePercentage =
      totalTests > 0 ? ((totalTests - failures) / totalTests) * 100 : 100;

    // Per-journey breakdown
    const journeyNames = ['login', 'deposit', 'trade', 'withdrawal'];
    const byJourney = await Promise.all(
      journeyNames.map(async (testName) => {
        const [jTotal, jFailures] = await Promise.all([
          this.prisma.syntheticTestResult.count({
            where: { testName, createdAt: { gte: startDate, lte: endDate } },
          }),
          this.prisma.syntheticTestResult.count({
            where: { testName, createdAt: { gte: startDate, lte: endDate }, success: false },
          }),
        ]);
        const uptime = jTotal > 0 ? ((jTotal - jFailures) / jTotal) * 100 : 100;
        return { testName, total: jTotal, failures: jFailures, uptime: Math.round(uptime * 1000) / 1000 };
      }),
    );

    return {
      startDate,
      endDate,
      uptimePercentage: Math.round(uptimePercentage * 1000) / 1000,
      targetUptime: SLA_TARGET_UPTIME,
      totalTests,
      failures,
      slaBreached: uptimePercentage < SLA_TARGET_UPTIME,
      byJourney,
    };
  }

  async getStatusPage(): Promise<
    Array<{ journey: string; status: 'operational' | 'degraded' | 'down'; lastCheckMs: number; location: string }>
  > {
    const journeyNames = ['login', 'deposit', 'trade', 'withdrawal'];
    const since = new Date(Date.now() - 15 * 60 * 1000); // last 15 minutes

    const statuses = await Promise.all(
      journeyNames.map(async (journey) => {
        const results = await this.prisma.syntheticTestResult.findMany({
          where: { testName: journey, createdAt: { gte: since } },
          orderBy: { createdAt: 'desc' },
          take: LOCATIONS.length,
        });

        if (results.length === 0) {
          return { journey, status: 'down' as const, lastCheckMs: 0, location: 'all' };
        }

        const failures = results.filter((r) => !r.success).length;
        const errorRate = (failures / results.length) * 100;
        const lastCheck = results[0];

        let status: 'operational' | 'degraded' | 'down' = 'operational';
        if (errorRate > 50) status = 'down';
        else if (errorRate > 10) status = 'degraded';

        return {
          journey,
          status,
          lastCheckMs: lastCheck.durationMs,
          location: lastCheck.location,
        };
      }),
    );

    return statuses;
  }

  async getTrends(
    testName: string,
    days: number,
  ): Promise<Array<{ date: string; avgLatencyMs: number; successRate: number; count: number }>> {
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const results = await this.prisma.syntheticTestResult.findMany({
      where: { testName, createdAt: { gte: since } },
      select: { durationMs: true, success: true, createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    // Group by day
    const byDay = new Map<string, { durations: number[]; successes: number; total: number }>();

    for (const r of results) {
      const day = r.createdAt.toISOString().split('T')[0];
      if (!byDay.has(day)) {
        byDay.set(day, { durations: [], successes: 0, total: 0 });
      }
      const entry = byDay.get(day)!;
      entry.durations.push(r.durationMs);
      entry.total += 1;
      if (r.success) entry.successes += 1;
    }

    const trends: Array<{ date: string; avgLatencyMs: number; successRate: number; count: number }> = [];
    for (const [date, data] of byDay.entries()) {
      const avgLatencyMs =
        data.durations.length > 0
          ? Math.round(data.durations.reduce((a, b) => a + b, 0) / data.durations.length)
          : 0;
      const successRate = data.total > 0 ? (data.successes / data.total) * 100 : 0;
      trends.push({ date, avgLatencyMs, successRate: Math.round(successRate * 100) / 100, count: data.total });
    }

    return trends.sort((a, b) => a.date.localeCompare(b.date));
  }

  private async postWithCircuit(
    url: string,
    data: Record<string, unknown>,
    config: Record<string, unknown>,
  ) {
    return this.circuitBreakerService.execute('internal-synthetic-http', () =>
      axios.post(url, data, config),
    );
  }
}
