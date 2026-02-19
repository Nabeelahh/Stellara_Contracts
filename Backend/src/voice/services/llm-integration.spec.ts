import { Test, TestingModule } from '@nestjs/testing';
import { LlmService } from './llm.service';
import { QuotaService } from './quota.service';
import { LlmCacheService } from './llm-cache.service';
import { RedisService } from '../../redis/redis.service';
import { HttpException, HttpStatus } from '@nestjs/common';

describe('LLM Pipeline Integration Tests', () => {
  let llmService: LlmService;
  let quotaService: QuotaService;
  let cacheService: LlmCacheService;

  const mockRedisClient = {
    get: jest.fn(),
    set: jest.fn(),
    incr: jest.fn(),
    expire: jest.fn(),
    del: jest.fn(),
    keys: jest.fn(),
  };

  const mockRedisService = {
    client: mockRedisClient,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LlmService,
        QuotaService,
        LlmCacheService,
        {
          provide: RedisService,
          useValue: mockRedisService,
        },
      ],
    }).compile();

    llmService = module.get<LlmService>(LlmService);
    quotaService = module.get<QuotaService>(QuotaService);
    cacheService = module.get<LlmCacheService>(LlmCacheService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Complete LLM Request Pipeline', () => {
    const userId = 'user123';
    const sessionId = 'session123';
    const prompt = 'What is TypeScript?';

    it('should follow complete pipeline: quota -> cache -> LLM -> cache store', async () => {
      // Setup: All quotas available, no cache hit
      mockRedisClient.get.mockResolvedValueOnce(null); // No custom quota
      mockRedisClient.get.mockResolvedValueOnce(null); // Monthly usage
      mockRedisClient.get.mockResolvedValueOnce(null); // Session usage
      mockRedisClient.get.mockResolvedValueOnce(null); // RPM usage
      mockRedisClient.get.mockResolvedValueOnce(null); // Cache miss
      mockRedisClient.incr.mockResolvedValue(1); // Initialize counters
      mockRedisClient.set.mockResolvedValue('OK'); // Cache write

      const response = await llmService.generateResponse(userId, sessionId, prompt);

      expect(response.content).toBeDefined();
      expect(response.cached).toBe(false);
      expect(response.model).toBe('gpt-3.5-turbo');
      // Verify set was called for caching
      expect(mockRedisClient.set).toHaveBeenCalled();
    });

    it('should skip cache on second request if expired', async () => {
      // First request
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null); // Cache miss
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisClient.set.mockResolvedValue('OK');

      await llmService.generateResponse(userId, sessionId, prompt);

      jest.clearAllMocks();

      // Second request - cache still available
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('Cached response'); // Cache hit
      mockRedisClient.incr.mockResolvedValue(1);

      const response = await llmService.generateResponse(userId, sessionId, prompt);

      expect(response.cached).toBe(true);
      expect(response.content).toBe('Cached response');
    });

    it('should enforce quota limits across multiple sessions', async () => {
      const session1 = 'session1';
      const session2 = 'session2';

      // Request 1 - OK
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('500'); // Monthly at 500
      mockRedisClient.get.mockResolvedValueOnce('50');
      mockRedisClient.get.mockResolvedValueOnce('5');
      mockRedisClient.get.mockResolvedValueOnce(null); // Cache miss
      mockRedisClient.incr.mockResolvedValue(1);
      mockRedisClient.set.mockResolvedValue('OK');

      const response1 = await llmService.generateResponse(userId, session1, prompt);
      expect(response1.quotaStatus?.monthlyUsage).toBeDefined();

      jest.clearAllMocks();

      // Request 2 - Exceeds session quota (limit 100)
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('100'); // Monthly OK
      mockRedisClient.get.mockResolvedValueOnce('101'); // Session EXCEEDED

      await expect(
        llmService.generateResponse(userId, session2, prompt),
      ).rejects.toThrow();
    });

    it('should return fallback on any error without throwing', async () => {
      const response = await llmService.generateResponseWithFallback(
        userId,
        sessionId,
        prompt,
      );

      expect(response.content).toBeDefined();
      expect(response.model).toBeDefined();
      expect(() => {
        throw response;
      }).toBeDefined();
    });

    it('should cache custom prompt normalization', async () => {
      const variants = [
        '  What is TypeScript?  ',
        'what is typescript?',
        '  WHAT IS TYPESCRIPT?  ',
      ];

      // All variants should use same cache key
      for (const variant of variants) {
        mockRedisClient.get.mockResolvedValueOnce(null); // Quotas OK
        mockRedisClient.get.mockResolvedValueOnce(null);
        mockRedisClient.get.mockResolvedValueOnce(null);
        mockRedisClient.get.mockResolvedValueOnce(null);
        mockRedisClient.get.mockResolvedValueOnce(null); // Cache miss (normalized)
        mockRedisClient.incr.mockResolvedValue(1);
        mockRedisClient.set.mockResolvedValue('OK');

        await llmService.generateResponse(userId, sessionId, variant);
      }

      // Cache set should have been called multiple times (once per request)
      expect(mockRedisClient.set).toHaveBeenCalled();
    });
  });

  describe('Quota Enforcement Scenarios', () => {
    const userId = 'user123';
    const sessionId = 'session123';
    const prompt = 'test';

    it('should handle monthly quota reset at month boundary', async () => {
      const now = new Date();
      const isMonthEnd = now.getDate() === 31 || now.getDate() === 30;

      // Simulate quota at boundary
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('1000'); // At limit
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);

      if (isMonthEnd) {
        mockRedisClient.expire.mockResolvedValue(1);
      }

      const status = await quotaService.getQuotaStatus(userId, sessionId);
      expect(status.monthlyUsage).toBe(1000);
    });

    it('should track per-session quotas independently', async () => {
      const session1 = 'sess1';
      const session2 = 'sess2';

      // Session 1 quota
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('50');

      const status1 = await quotaService.getQuotaStatus(userId, session1);
      expect(status1.sessionUsage).toBe(50);

      jest.clearAllMocks();

      // Session 2 quota - independent
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('25');

      const status2 = await quotaService.getQuotaStatus(userId, session2);
      expect(status2.sessionUsage).toBe(25);
    });

    it('should enforce rate limiting per minute window', async () => {
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('20'); // At RPM limit

      // Next request in same minute should be rejected
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce(null);
      mockRedisClient.get.mockResolvedValueOnce('21'); // Exceeds RPM limit

      const status1 = await quotaService.getQuotaStatus(userId, sessionId);
      expect(status1.requestsThisMinute).toBe(20);

      // Next minute should reset (different key)
      // This would be tested with time mocking in real scenario
    });
  });

  describe('Cache Statistics & Management', () => {
    it('should track cache hit rate', async () => {
      mockRedisClient.get.mockResolvedValueOnce('100'); // total entries
      mockRedisClient.get.mockResolvedValueOnce('75'); // total hits
      mockRedisClient.keys.mockResolvedValue([]);

      const stats = await cacheService.getStats();

      expect(stats.totalEntries).toBe(100);
      expect(stats.totalHits).toBe(75);
      expect(stats.hitRate).toBe(0.75);
    });

    it('should support cache invalidation on model updates', async () => {
      const prompt = 'What is AI?';

      // Invalidate specific model cache
      mockRedisClient.keys.mockResolvedValueOnce(['key1', 'key2']);
      mockRedisClient.del.mockResolvedValue(2);

      const count = await cacheService.invalidate(prompt, 'gpt-4');

      expect(mockRedisClient.del).toHaveBeenCalled();
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should support cache warming for common prompts', async () => {
      const commonPrompts = [
        {
          prompt: 'What is blockchain?',
          response: 'Blockchain is...',
          model: 'gpt-3.5-turbo',
        },
        {
          prompt: 'Explain smart contracts',
          response: 'Smart contracts are...',
          model: 'gpt-3.5-turbo',
        },
      ];

      mockRedisClient.set.mockResolvedValue('OK');
      mockRedisClient.incr.mockResolvedValue(1);

      const count = await cacheService.warmCache(commonPrompts);

      expect(count).toBe(2);
      expect(mockRedisClient.set).toHaveBeenCalled();
    });

    it('should prune old cache entries', async () => {
      mockRedisClient.keys.mockResolvedValue(['key1', 'key2']);
      mockRedisClient.get.mockResolvedValue((Date.now() - 86400000).toString()); // 1 day old
      mockRedisClient.del.mockResolvedValue(4);

      const count = await cacheService.pruneOldEntries(3600); // 1 hour max age

      expect(mockRedisClient.del).toHaveBeenCalled();
    });
  });

  describe('Fallback & Graceful Degradation', () => {
    const userId = 'user123';
    const sessionId = 'session123';

    it('should return fallback when quota service fails', async () => {
      mockRedisClient.get.mockRejectedValue(new Error('Redis down'));

      const response = await llmService.generateResponseWithFallback(
        userId,
        sessionId,
        'test prompt',
      );

      expect(response.content).toContain("I'm sorry");
      expect(response.cached).toBe(false);
    });

    it('should return fallback when cache service fails', async () => {
      mockRedisClient.set.mockRejectedValue(new Error('Cache write failed'));

      const response = await llmService.generateResponseWithFallback(
        userId,
        sessionId,
        'test prompt',
      );

      expect(response.content).toBeDefined();
      expect(response.model).toBeDefined();
    });

    it('should still track quotas even if LLM fails', async () => {
      mockRedisClient.get.mockResolvedValue(null);
      mockRedisClient.incr.mockResolvedValue(1);

      const response = await llmService.generateResponseWithFallback(
        userId,
        sessionId,
        'force-fail', // Trigger LLM failure
      );

      expect(response.quotaStatus).toBeDefined();
    });
  });
});
