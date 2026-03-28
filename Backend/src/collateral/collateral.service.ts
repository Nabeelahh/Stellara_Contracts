import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { OracleService } from './oracle.service';
import { PledgeCollateralDto, SubstitutionDto, LoanRequestDto } from './dto/collateral.dto';
import { Prisma } from '@prisma/client';
import { Cron, CronExpression } from '@nestjs/schedule';

export enum MarginAccountStatus {
  HEALTHY = 'HEALTHY',
  MARGIN_CALL = 'MARGIN_CALL',
  LIQUIDATION_PENDING = 'LIQUIDATION_PENDING',
  LIQUIDATED = 'LIQUIDATED',
}

@Injectable()
export class CollateralService {
  private readonly logger = new Logger(CollateralService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly oracle: OracleService,
  ) {}

  /**
   * Seed default collateral assets
   */
  async seedDefaultAssets() {
    const assets = [
      { symbol: 'XLM', name: 'Stellar Lumens', haircut: 0.15, minPledgeAmount: 1.0 },
      { symbol: 'BTC', name: 'Bitcoin', haircut: 0.1, minPledgeAmount: 0.0001 },
      { symbol: 'ETH', name: 'Ethereum', haircut: 0.12, minPledgeAmount: 0.001 },
      { symbol: 'USDC', name: 'USD Coin', haircut: 0.05, minPledgeAmount: 1.0 },
      { symbol: 'USDT', name: 'Tether', haircut: 0.05, minPledgeAmount: 1.0 },
    ];

    for (const asset of assets) {
      await this.prisma.collateralAsset.upsert({
        where: { symbol: asset.symbol },
        update: asset,
        create: asset,
      });
    }
  }

  /**
   * Pledge collateral to a margin account
   */
  async pledgeCollateral(dto: PledgeCollateralDto) {
    const { userId, symbol, amount } = dto;

    const asset = await this.prisma.collateralAsset.findUnique({
      where: { symbol: symbol.toUpperCase() },
    });

    if (!asset || !asset.isActive) {
      throw new BadRequestException(`Asset ${symbol} is not a valid or active collateral asset`);
    }

    if (amount < Number(asset.minPledgeAmount)) {
      throw new BadRequestException(`Amount ${amount} is below minimum pledge amount ${asset.minPledgeAmount}`);
    }

    // Get or create margin account
    let marginAccount = await this.prisma.marginAccount.findUnique({
      where: { userId },
    });

    if (!marginAccount) {
      marginAccount = await this.prisma.marginAccount.create({
        data: { userId },
      });
    }

    // Update or create pledge
    await this.prisma.collateralPledge.upsert({
      where: {
        marginAccountId_assetSymbol: {
          marginAccountId: marginAccount.id,
          assetSymbol: asset.symbol,
        },
      },
      update: {
        amount: { increment: amount },
      },
      create: {
        marginAccountId: marginAccount.id,
        assetSymbol: asset.symbol,
        amount: amount,
      },
    });

    return this.calculateAccountHealth(userId);
  }

  /**
   * Substitute collateral: Withdraw one asset and deposit another
   */
  async substituteCollateral(dto: SubstitutionDto) {
    const { userId, withdrawSymbol, withdrawAmount, depositSymbol, depositAmount } = dto;

    const marginAccount = await this.prisma.marginAccount.findUnique({
      where: { userId },
      include: { pledges: true },
    });

    if (!marginAccount) {
      throw new NotFoundException('Margin account not found');
    }

    const pledge = marginAccount.pledges.find(p => p.assetSymbol === withdrawSymbol.toUpperCase());
    if (!pledge || Number(pledge.amount) < withdrawAmount) {
      throw new BadRequestException('Insufficient collateral to withdraw');
    }

    // Use transaction to ensure both operations succeed
    return await this.prisma.$transaction(async (tx) => {
      // Deposit new collateral
      await this.pledgeCollateral({ userId, symbol: depositSymbol, amount: depositAmount });

      // Withdraw old collateral
      await tx.collateralPledge.update({
        where: {
          marginAccountId_assetSymbol: {
            marginAccountId: marginAccount.id,
            assetSymbol: withdrawSymbol.toUpperCase(),
          },
        },
        data: {
          amount: { decrement: withdrawAmount },
        },
      });

      // Verify health after substitution
      const health = await this.calculateAccountHealth(userId);
      if (health.status === MarginAccountStatus.LIQUIDATION_PENDING) {
        throw new BadRequestException('Substitution would result in liquidation risk');
      }

      return health;
    });
  }

  /**
   * Request a loan
   */
  async requestLoan(dto: LoanRequestDto) {
    const { userId, symbol, amount } = dto;

    const marginAccount = await this.prisma.marginAccount.findUnique({
      where: { userId },
    });

    if (!marginAccount) {
      throw new BadRequestException('Margin account not found. Please pledge collateral first.');
    }

    // Check if new loan would violate LTV (e.g. max 70% LTV for new loans)
    const currentHealth = await this.calculateAccountHealth(userId);
    const assetPrice = await this.oracle.getPrice(symbol);
    const loanValueUsd = amount * assetPrice;

    const newTotalBorrowed = Number(currentHealth.totalBorrowed) + loanValueUsd;
    const newLtv = newTotalBorrowed / Number(currentHealth.totalCollateralValueUsd);

    if (newLtv > 0.7) {
      throw new BadRequestException(`Loan request exceeds maximum initial LTV of 70%. Proposed LTV: ${(newLtv * 100).toFixed(2)}%`);
    }

    await this.prisma.loan.create({
      data: {
        marginAccountId: marginAccount.id,
        assetSymbol: symbol.toUpperCase(),
        amount: amount,
        interestRate: 0.05, // 5% annual interest
      },
    });

    return this.calculateAccountHealth(userId);
  }

  /**
   * Calculate account health, LTV, and valuation
   */
  async calculateAccountHealth(userId: string) {
    const marginAccount = await this.prisma.marginAccount.findUnique({
      where: { userId },
      include: {
        pledges: { include: { asset: true } },
        loans: { where: { status: 'ACTIVE' } },
      },
    });

    if (!marginAccount) {
      throw new NotFoundException('Margin account not found');
    }

    let totalCollateralValueUsd = 0;
    let totalCollateralAdjustedUsd = 0; // After haircuts

    for (const pledge of marginAccount.pledges) {
      const price = await this.oracle.getPrice(pledge.assetSymbol);
      const valueUsd = Number(pledge.amount) * price;
      totalCollateralValueUsd += valueUsd;
      
      const haircut = Number(pledge.asset.haircut);
      totalCollateralAdjustedUsd += valueUsd * (1 - haircut);

      // Update last valuation
      await this.prisma.collateralPledge.update({
        where: { id: pledge.id },
        data: { lastValuationUsd: valueUsd },
      });
    }

    let totalBorrowedUsd = 0;
    for (const loan of marginAccount.loans) {
      const price = await this.oracle.getPrice(loan.assetSymbol);
      const loanPrincipal = Number(loan.amount);
      const interest = Number(loan.accruedInterest);
      totalBorrowedUsd += (loanPrincipal + interest) * price;
    }

    const ltvRatio = totalCollateralValueUsd > 0 ? totalBorrowedUsd / totalCollateralValueUsd : 0;
    const healthFactor = totalBorrowedUsd > 0 ? totalCollateralAdjustedUsd / totalBorrowedUsd : 100;

    let status = MarginAccountStatus.HEALTHY;
    if (ltvRatio >= 0.9) {
      status = MarginAccountStatus.LIQUIDATION_PENDING;
    } else if (ltvRatio >= 0.8) {
      status = MarginAccountStatus.MARGIN_CALL;
    }

    const lastMarginCallAt = status === MarginAccountStatus.MARGIN_CALL ? new Date() : marginAccount.lastMarginCallAt;

    const updatedAccount = await this.prisma.marginAccount.update({
      where: { id: marginAccount.id },
      data: {
        totalBorrowed: totalBorrowedUsd,
        totalCollateralUsd: totalCollateralValueUsd,
        ltvRatio: ltvRatio,
        healthFactor: healthFactor,
        status: status as any,
        lastMarginCallAt,
      },
    });

    return {
      ...updatedAccount,
      totalCollateralValueUsd,
      totalCollateralAdjustedUsd,
      totalBorrowedUsd,
      ltvRatio,
      healthFactor,
    };
  }

  /**
   * Accrue interest on all active loans
   * Runs daily at midnight
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async accrueInterest() {
    this.logger.log('Starting interest accrual for all active loans');
    
    const activeLoans = await this.prisma.loan.findMany({
      where: { status: 'ACTIVE' },
    });

    for (const loan of activeLoans) {
      const dailyRate = Number(loan.interestRate) / 365;
      const dailyInterest = Number(loan.amount) * dailyRate;

      await this.prisma.loan.update({
        where: { id: loan.id },
        data: {
          accruedInterest: { increment: dailyInterest },
          lastInterestAccrual: new Date(),
        },
      });
    }

    this.logger.log(`Accrued interest for ${activeLoans.length} loans`);
  }
}
