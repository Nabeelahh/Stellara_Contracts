import { CollateralService, MarginAccountStatus } from './collateral.service';

describe('CollateralService', () => {
  let service: CollateralService;
  let prisma: any;
  let oracle: any;

  beforeEach(() => {
    prisma = {
      collateralAsset: {
        findUnique: jest.fn(),
        upsert: jest.fn(),
      },
      marginAccount: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      collateralPledge: {
        upsert: jest.fn(),
        update: jest.fn(),
      },
      loan: {
        create: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
      },
      $transaction: jest.fn((cb) => cb(prisma)),
    };
    oracle = {
      getPrice: jest.fn(),
    };
    service = new CollateralService(prisma, oracle);
  });

  it('calculates account health correctly', async () => {
    const userId = 'user-1';
    
    // Setup mocks
    prisma.marginAccount.findUnique.mockResolvedValue({
      id: 'acc-1',
      userId,
      pledges: [
        {
          id: 'pledge-1',
          assetSymbol: 'XLM',
          amount: 1000,
          asset: { haircut: 0.15 }
        }
      ],
      loans: [
        {
          id: 'loan-1',
          assetSymbol: 'USDC',
          amount: 50,
          accruedInterest: 1,
          status: 'ACTIVE'
        }
      ]
    });

    oracle.getPrice.mockImplementation((symbol: string) => {
      if (symbol === 'XLM') return 0.10;
      if (symbol === 'USDC') return 1.0;
      return 0;
    });

    prisma.marginAccount.update.mockImplementation((args: any) => args.data);

    const health = await service.calculateAccountHealth(userId);

    // Collateral: 1000 * 0.10 = 100 USD
    // Adjusted: 100 * (1 - 0.15) = 85 USD
    // Borrowed: (50 + 1) * 1.0 = 51 USD
    // LTV: 51 / 100 = 0.51
    // Health Factor: 85 / 51 = 1.666...

    expect(health.totalCollateralValueUsd).toBe(100);
    expect(health.totalBorrowedUsd).toBe(51);
    expect(health.ltvRatio).toBe(0.51);
    expect(health.status).toBe(MarginAccountStatus.HEALTHY);
  });

  it('sets status to MARGIN_CALL when LTV >= 0.8', async () => {
    const userId = 'user-1';
    
    prisma.marginAccount.findUnique.mockResolvedValue({
      id: 'acc-1',
      userId,
      pledges: [{ id: 'p1', assetSymbol: 'BTC', amount: 1, asset: { haircut: 0.1 } }],
      loans: [{ id: 'l1', assetSymbol: 'USDC', amount: 8500, accruedInterest: 0, status: 'ACTIVE' }]
    });

    oracle.getPrice.mockImplementation((symbol: string) => {
      if (symbol === 'BTC') return 10000;
      if (symbol === 'USDC') return 1.0;
      return 0;
    });

    prisma.marginAccount.update.mockImplementation((args: any) => args.data);

    const health = await service.calculateAccountHealth(userId);

    // Collateral: 10000 USD
    // Borrowed: 8500 USD
    // LTV: 0.85
    expect(health.ltvRatio).toBe(0.85);
    expect(health.status).toBe(MarginAccountStatus.MARGIN_CALL);
  });

  it('sets status to LIQUIDATION_PENDING when LTV >= 0.9', async () => {
    const userId = 'user-1';
    
    prisma.marginAccount.findUnique.mockResolvedValue({
      id: 'acc-1',
      userId,
      pledges: [{ id: 'p1', assetSymbol: 'BTC', amount: 1, asset: { haircut: 0.1 } }],
      loans: [{ id: 'l1', assetSymbol: 'USDC', amount: 9500, accruedInterest: 0, status: 'ACTIVE' }]
    });

    oracle.getPrice.mockImplementation((symbol: string) => {
      if (symbol === 'BTC') return 10000;
      if (symbol === 'USDC') return 1.0;
      return 0;
    });

    prisma.marginAccount.update.mockImplementation((args: any) => args.data);

    const health = await service.calculateAccountHealth(userId);

    // Collateral: 10000 USD
    // Borrowed: 9500 USD
    // LTV: 0.95
    expect(health.ltvRatio).toBe(0.95);
    expect(health.status).toBe(MarginAccountStatus.LIQUIDATION_PENDING);
  });
});
