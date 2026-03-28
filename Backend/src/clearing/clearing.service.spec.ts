import { ClearingService } from './clearing.service';
import { PrismaService } from '../prisma.service';
import { CreateTradeDto } from './dto/create-trade.dto';

describe('ClearingService', () => {
  let service: ClearingService;
  let mockPrisma: Partial<PrismaService>;

  beforeEach(() => {
    mockPrisma = {
      clearingPosition: {
        create: jest.fn().mockResolvedValue({}),
      } as any,
      clearingMarginAccount: {
        upsert: jest.fn().mockResolvedValue({}),
        update: jest.fn().mockResolvedValue({}),
      } as any,
      clearingSettlement: {
        create: jest.fn().mockResolvedValue({}),
      } as any,
      defaultFundContribution: {
        create: jest.fn().mockResolvedValue({}),
      } as any,
      clearingAuction: {
        create: jest.fn().mockResolvedValue({ id: 'auction1' }),
      } as any,
    };

    // @ts-ignore - inject partial mock
    service = new ClearingService(mockPrisma as PrismaService);
  });

  test('acceptTrade reserves margins and persists positions', async () => {
    const trade: CreateTradeDto = {
      tradeId: 't1',
      buyerId: 'm1',
      sellerId: 'm2',
      instrument: 'BTC-USD-FUT',
      notional: 10,
      price: 25000,
      timestamp: Date.now(),
    };

    const res = await service.acceptTrade(trade);
    expect(res).toHaveProperty('buyPosId');
    expect(res).toHaveProperty('sellPosId');
    // prisma create called twice for positions
    expect((mockPrisma.clearingPosition!.create as jest.Mock).mock.calls.length).toBe(2);
    // upsert margin accounts called for both members
    expect((mockPrisma.clearingMarginAccount!.upsert as jest.Mock).mock.calls.length).toBe(2);
    // update called for reserved margins
    expect((mockPrisma.clearingMarginAccount!.update as jest.Mock).mock.calls.length).toBe(2);
  });

  test('contributeDefaultFund records contribution', async () => {
    // Start with zero
    service.contributeDefaultFund('m1', 1000);
    // in-memory updated
    expect(service.getDefaultFund().total).toBe(1000);
    // prisma create called
    expect((mockPrisma.defaultFundContribution!.create as jest.Mock).mock.calls.length).toBe(1);
  });

  test('settleMarkToMarket persists settlement and computes variations', async () => {
    // create two positions directly in memory for instrument
    service['positions'].set('p1', {
      positionId: 'p1',
      memberId: 'm1',
      instrument: 'BTC-USD-FUT',
      quantity: 2,
      avgPrice: 20000,
      unrealizedPnl: 0,
    });
    service['positions'].set('p2', {
      positionId: 'p2',
      memberId: 'm2',
      instrument: 'BTC-USD-FUT',
      quantity: -2,
      avgPrice: 20000,
      unrealizedPnl: 0,
    });

    const res = await service.settleMarkToMarket('BTC-USD-FUT', 21000);
    expect(res).toHaveProperty('instrument', 'BTC-USD-FUT');
    expect((mockPrisma.clearingSettlement!.create as jest.Mock).mock.calls.length).toBe(1);
  });

  test('startAuctionForDefault creates auction record', async () => {
    const r = await service.startAuctionForDefault('m_bad');
    expect(r).toHaveProperty('auctionId');
    expect((mockPrisma.clearingAuction!.create as jest.Mock).mock.calls.length).toBe(1);
  });
});
