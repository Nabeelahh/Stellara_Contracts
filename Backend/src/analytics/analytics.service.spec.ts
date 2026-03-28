import { Test, TestingModule } from '@nestjs/testing';
import { AnalyticsService } from './analytics.service';
import { PrismaService } from '../prisma.service';

describe('AnalyticsService', () => {
  let service: AnalyticsService;
  let prisma: PrismaService;

  const mockPrisma = {
    user: {
      findUnique: jest.fn(),
    },
    stakeLedger: {
      findMany: jest.fn(),
    },
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalyticsService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();

    service = module.get<AnalyticsService>(AnalyticsService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should calculate performance metrics correctly', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({ walletAddress: '0x123' });
    mockPrisma.stakeLedger.findMany.mockResolvedValue([
      { amount: 100, profitLoss: 50, createdAt: new Date(), resolutionStatus: 'RESOLVED', callId: '1' },
      { amount: 100, profitLoss: -20, createdAt: new Date(), resolutionStatus: 'RESOLVED', callId: '2' },
    ]);

    const metrics = await service.getPerformanceMetrics('user1');
    expect(metrics.totalPnL).toBe(30);
    expect(metrics.winRate).toBe(50);
    expect(metrics.totalTrades).toBe(2);
    expect(metrics.maxDrawdown).toBeGreaterThanOrEqual(0);
  });

  it('should calculate behavioral stats correctly', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({ walletAddress: '0x123' });
    mockPrisma.stakeLedger.findMany.mockResolvedValue([
      { amount: 100, profitLoss: 50, createdAt: new Date(), resolutionStatus: 'RESOLVED', callId: 'BTC-USD' },
      { amount: 100, profitLoss: -20, createdAt: new Date(), resolutionStatus: 'RESOLVED', callId: 'ETH-USD' },
    ]);

    const stats = await service.getBehavioralAnalysis('user1');
    expect(stats.bestPairs[0].callId).toBe('BTC-USD');
    expect(stats.worstPairs[0].callId).toBe('ETH-USD');
  });

  it('should generate recommendations based on drawdown', async () => {
    mockPrisma.user.findUnique.mockResolvedValue({ walletAddress: '0x123' });
    mockPrisma.stakeLedger.findMany.mockResolvedValue([
      { amount: 100, profitLoss: -3000, createdAt: new Date(), resolutionStatus: 'RESOLVED', callId: '1' },
    ]);

    const recommendations = await service.getRecommendations('user1');
    expect(recommendations).toContain('Your maximum drawdown is high. Consider reducing position sizes.');
  });
});
