/**
 * Rate Limiting Integration Tests
 * Test suite for distributed rate limiting system
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DistributedRateLimitService, RateLimitIdentifier } from './distributed-rate-limit.service';
import { RoleBasedRateLimitService, UserRole, EndpointCategory } from './role-based-rate-limit.service';
import { RateLimitMetricsCollector } from './rate-limit-metrics.collector';
import { RedisService } from '../redis/redis.service';
import { RedisModule } from '../redis/redis.module';

describe('Rate Limiting System', () => {
  let module: TestingModule;
  let rateLimitService: DistributedRateLimitService;
  let roleBasedService: RoleBasedRateLimitService;
  let metricsCollector: RateLimitMetricsCollector;
  let redisService: RedisService;

  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [RedisModule],
      providers: [
        DistributedRateLimitService,
        RoleBasedRateLimitService,
        RateLimitMetricsCollector,
      ],
    }).compile();

    redisService = module.get<RedisService>(RedisService);
    rateLimitService = module.get<DistributedRateLimitService>(
      DistributedRateLimitService,
    );
    roleBasedService = module.get<RoleBasedRateLimitService>(
      RoleBasedRateLimitService,
    );
    metricsCollector = module.get<RateLimitMetricsCollector>(
      RateLimitMetricsCollector,
    );
  });

  afterAll(async () => {
    await module.close();
  });

  describe('DistributedRateLimitService', () => {
    it('should check rate limit and allow request', async () => {
      const identifier: RateLimitIdentifier = {
        ip: '192.168.1.1',
        path: '/api/test',
      };

      const config = { limit: 10, window: 60 };

      const result = await rateLimitService.checkRateLimit(
        identifier,
        config,
      );

      expect(result.allowed).toBe(true);
      expect(result.current).toBeGreaterThan(0);
      expect(result.remaining).toBeLessThan(config.limit);
    });

    it('should detect rate limit violation', async () => {
      const identifier: RateLimitIdentifier = {
        ip: '192.168.1.2',
        path: '/api/test',
      };

      const config = { limit: 2, window: 60 };

      // Make requests up to limit
      await rateLimitService.checkRateLimit(identifier, config);
      await rateLimitService.checkRateLimit(identifier, config);

      // Third request should be blocked
      const result = await rateLimitService.checkRateLimit(
        identifier,
        config,
      );

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should track violations', async () => {
      const identifier: RateLimitIdentifier = {
        ip: '192.168.1.3',
        path: '/api/test',
      };

      const config = { limit: 1, window: 60 };

      // Trigger violation
      await rateLimitService.checkRateLimit(identifier, config);
      await rateLimitService.checkRateLimit(identifier, config);

      const metrics = await rateLimitService.getMetrics(identifier);

      expect(metrics.violations).toBeGreaterThan(0);
    });

    it('should ban after excessive violations', async () => {
      const identifier: RateLimitIdentifier = {
        ip: '192.168.1.4',
        path: '/api/test',
      };

      const config = { limit: 1, window: 60 };

      // Trigger multiple violations
      for (let i = 0; i < 15; i++) {
        await rateLimitService.checkRateLimit(identifier, config);
      }

      const metrics = await rateLimitService.getMetrics(identifier);

      // Should be banned after 10 violations
      expect(metrics.isBanned).toBe(true);
    });

    it('should reset rate limit', async () => {
      const identifier: RateLimitIdentifier = {
        ip: '192.168.1.5',
        path: '/api/test',
      };

      const config = { limit: 2, window: 60 };

      // Trigger violation
      await rateLimitService.checkRateLimit(identifier, config);
      await rateLimitService.checkRateLimit(identifier, config);

      // Reset
      await rateLimitService.resetRateLimit(identifier);

      // Should allow request again
      const result = await rateLimitService.checkRateLimit(
        identifier,
        config,
      );

      expect(result.current).toBe(1);
    });

    it('should ban and unban identifier', async () => {
      const identifier: RateLimitIdentifier = {
        ip: '192.168.1.6',
        path: '/api/test',
      };

      // Ban
      await rateLimitService.banIdentifier(identifier, 3600);
      let isBanned = await rateLimitService.isBanned(identifier);
      expect(isBanned).toBe(true);

      // Unban
      await rateLimitService.unbanIdentifier(identifier);
      isBanned = await rateLimitService.isBanned(identifier);
      expect(isBanned).toBe(false);
    });
  });

  describe('RoleBasedRateLimitService', () => {
    it('should return different limits for different roles', () => {
      const adminLimit = roleBasedService.getRateLimit(
        UserRole.ADMIN,
        EndpointCategory.PUBLIC,
      );
      const userLimit = roleBasedService.getRateLimit(
        UserRole.USER,
        EndpointCategory.PUBLIC,
      );
      const anonLimit = roleBasedService.getRateLimit(
        UserRole.ANONYMOUS,
        EndpointCategory.PUBLIC,
      );

      expect(adminLimit.limit).toBeGreaterThan(userLimit.limit);
      expect(userLimit.limit).toBeGreaterThan(anonLimit.limit);
    });

    it('should block access for unauthorized roles', () => {
      const canAccess = roleBasedService.canAccessEndpoint(
        UserRole.ANONYMOUS,
        EndpointCategory.TRADING,
      );

      expect(canAccess).toBe(false);
    });

    it('should allow access for authorized roles', () => {
      const canAccess = roleBasedService.canAccessEndpoint(
        UserRole.USER,
        EndpointCategory.TRADING,
      );

      expect(canAccess).toBe(true);
    });

    it('should update rate limits', () => {
      const originalLimit = roleBasedService.getRateLimit(
        UserRole.USER,
        EndpointCategory.PUBLIC,
      );

      roleBasedService.updateRateLimit(
        UserRole.USER,
        EndpointCategory.PUBLIC,
        { limit: 9999, window: 120 },
      );

      const updatedLimit = roleBasedService.getRateLimit(
        UserRole.USER,
        EndpointCategory.PUBLIC,
      );

      expect(updatedLimit.limit).toBe(9999);
      expect(updatedLimit.window).toBe(120);

      // Restore
      roleBasedService.updateRateLimit(
        UserRole.USER,
        EndpointCategory.PUBLIC,
        originalLimit,
      );
    });

    it('should get rate limit summary', () => {
      const summary = roleBasedService.getSummary();

      expect(summary[UserRole.ADMIN]).toBeDefined();
      expect(summary[UserRole.USER]).toBeDefined();
      expect(summary[UserRole.ANONYMOUS]).toBeDefined();
    });
  });

  describe('RateLimitMetricsCollector', () => {
    it('should record violations', () => {
      expect(() => {
        metricsCollector.recordViolation(
          '192.168.1.7',
          'user123',
          '/api/test',
        );
      }).not.toThrow();
    });

    it('should record blocked requests', () => {
      expect(() => {
        metricsCollector.recordBlockedRequest(
          '192.168.1.8',
          'user456',
          '/api/test',
        );
      }).not.toThrow();
    });

    it('should get current metrics', async () => {
      const metrics = await metricsCollector.getCurrentMetrics();

      expect(metrics).toHaveProperty('totalRequests');
      expect(metrics).toHaveProperty('violatedRequests');
      expect(metrics).toHaveProperty('bannedIdentifiers');
      expect(metrics).toHaveProperty('violationRate');
    });

    it('should get Prometheus metrics', () => {
      const prometheusMetrics = metricsCollector.getPrometheusMetrics();

      expect(prometheusMetrics).toBeTruthy();
      expect(prometheusMetrics).toContain('rate_limit');
    });
  });
});
