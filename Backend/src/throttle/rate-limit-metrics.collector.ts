/**
 * Rate Limit Metrics Collector
 * Collects and exposes metrics for rate limiting monitoring and alerting
 */

import { Injectable, Logger } from '@nestjs/common';
import { register, Counter, Gauge, Histogram } from 'prom-client';
import { DistributedRateLimitService } from './distributed-rate-limit.service';

/**
 * Rate limit metrics interface
 */
export interface RateLimitMetrics {
  totalRequests: number;
  violatedRequests: number;
  bannedIdentifiers: number;
  activeKeys: number;
  violationRate: number;
  avgViolationsPerKey: number;
}

/**
 * Rate limit metrics collector
 */
@Injectable()
export class RateLimitMetricsCollector {
  private readonly logger = new Logger('RateLimitMetrics');

  // Prometheus metrics
  private rateLimitViolationsCounter: Counter;
  private rateLimitBlockedCounter: Counter;
  private bannedIdentifiersGauge: Gauge;
  private activeKeysGauge: Gauge;
  private violationDurationHistogram: Histogram;
  private requestsPerIdentifierGauge: Gauge;

  constructor(
    private readonly rateLimitService: DistributedRateLimitService,
  ) {
    this.initializeMetrics();
  }

  /**
   * Initialize Prometheus metrics
   */
  private initializeMetrics(): void {
    // Violations counter
    this.rateLimitViolationsCounter = new Counter({
      name: 'rate_limit_violations_total',
      help: 'Total number of rate limit violations',
      labelNames: ['ip', 'user_id', 'endpoint'],
      registers: [register],
    });

    // Blocked requests counter
    this.rateLimitBlockedCounter = new Counter({
      name: 'rate_limit_blocked_total',
      help: 'Total number of requests blocked due to rate limiting',
      labelNames: ['ip', 'user_id', 'endpoint'],
      registers: [register],
    });

    // Banned identifiers gauge
    this.bannedIdentifiersGauge = new Gauge({
      name: 'rate_limit_banned_identifiers',
      help: 'Number of currently banned identifiers',
      registers: [register],
    });

    // Active keys gauge
    this.activeKeysGauge = new Gauge({
      name: 'rate_limit_active_keys',
      help: 'Number of active rate limiting keys',
      registers: [register],
    });

    // Violation duration histogram
    this.violationDurationHistogram = new Histogram({
      name: 'rate_limit_violation_duration_seconds',
      help: 'Duration between violations in seconds',
      labelNames: ['ip'],
      buckets: [1, 5, 10, 30, 60, 300, 600, 1800],
      registers: [register],
    });

    // Requests per identifier gauge
    this.requestsPerIdentifierGauge = new Gauge({
      name: 'rate_limit_requests_per_identifier',
      help: 'Average requests per identifier in current window',
      registers: [register],
    });

    this.logger.log('Prometheus metrics initialized');
  }

  /**
   * Record rate limit violation
   */
  recordViolation(
    ip: string,
    userId: string | undefined,
    endpoint: string,
  ): void {
    this.rateLimitViolationsCounter.inc(
      {
        ip,
        user_id: userId || 'anonymous',
        endpoint,
      },
      1,
    );
  }

  /**
   * Record blocked request
   */
  recordBlockedRequest(
    ip: string,
    userId: string | undefined,
    endpoint: string,
  ): void {
    this.rateLimitBlockedCounter.inc(
      {
        ip,
        user_id: userId || 'anonymous',
        endpoint,
      },
      1,
    );
  }

  /**
   * Record violation duration
   */
  recordViolationDuration(ip: string, durationSeconds: number): void {
    this.violationDurationHistogram.observe({ ip }, durationSeconds);
  }

  /**
   * Update system-wide metrics
   */
  async updateSystemMetrics(): Promise<void> {
    try {
      const stats = await this.rateLimitService.getSystemStats();

      this.bannedIdentifiersGauge.set(stats.bannedIdentifiers);
      this.activeKeysGauge.set(stats.totalActiveKeys);
      this.requestsPerIdentifierGauge.set(
        stats.totalActiveKeys > 0
          ? stats.totalViolations / stats.totalActiveKeys
          : 0,
      );
    } catch (error) {
      this.logger.error('Failed to update system metrics:', error);
    }
  }

  /**
   * Get current metrics
   */
  async getCurrentMetrics(): Promise<RateLimitMetrics> {
    const stats = await this.rateLimitService.getSystemStats();

    return {
      totalRequests: stats.totalActiveKeys,
      violatedRequests: stats.totalViolations,
      bannedIdentifiers: stats.bannedIdentifiers,
      activeKeys: stats.totalActiveKeys,
      violationRate: stats.totalActiveKeys > 0
        ? (stats.totalViolations / stats.totalActiveKeys) * 100
        : 0,
      avgViolationsPerKey: stats.totalActiveKeys > 0
        ? stats.totalViolations / stats.totalActiveKeys
        : 0,
    };
  }

  /**
   * Get metrics in Prometheus format
   */
  getPrometheusMetrics(): string {
    return register.metrics();
  }
}
