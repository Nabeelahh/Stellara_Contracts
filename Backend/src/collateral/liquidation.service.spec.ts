import { LiquidationService } from './liquidation.service';
import { MarginAccountStatus } from './collateral.service';

describe('LiquidationService', () => {
  let service: LiquidationService;
  let prisma: any;
  let oracle: any;
  let collateralService: any;

  beforeEach(() => {
    prisma = {
      marginAccount: {
        findMany: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
      },
      collateralPledge: {
        update: jest.fn(),
      },
      loan: {
        update: jest.fn(),
      },
      liquidation: {
        create: jest.fn(),
      },
      $transaction: jest.fn((cb) => cb(prisma)),
    };
    oracle = {
      getPrice: jest.fn(),
    };
    collateralService = {
      calculateAccountHealth: jest.fn(),
    };
    service = new LiquidationService(prisma, oracle, collateralService);
  });

  it('liquidates an account when LIQUIDATION_PENDING', async () => {
    const userId = 'user-1';
    
    collateralService.calculateAccountHealth.mockResolvedValue({
      status: MarginAccountStatus.LIQUIDATION_PENDING,
      ltvRatio: 0.95,
      totalBorrowedUsd: 9500,
      totalCollateralValueUsd: 10000,
    });

    prisma.marginAccount.findUnique.mockResolvedValue({
      id: 'acc-1',
      userId,
      pledges: [
        {
          id: 'p1',
          assetSymbol: 'BTC',
          amount: 1,
          lastValuationUsd: 10000,
          asset: { haircut: 0.1 }
        }
      ],
      loans: [
        {
          id: 'l1',
          assetSymbol: 'USDC',
          amount: 9500,
          accruedInterest: 0,
          status: 'ACTIVE'
        }
      ]
    });

    oracle.getPrice.mockImplementation((symbol: string) => {
      if (symbol === 'BTC') return 10000;
      if (symbol === 'USDC') return 1.0;
      return 0;
    });

    await service.liquidateAccount(userId, 'liquidator-1', true);

    // Verify collateral was reduced
    expect(prisma.collateralPledge.update).toHaveBeenCalled();
    // Verify loan was updated
    expect(prisma.loan.update).toHaveBeenCalled();
    // Verify liquidation was recorded
    expect(prisma.liquidation.create).toHaveBeenCalled();
  });
});
