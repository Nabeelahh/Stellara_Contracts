import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { OracleService } from './oracle.service';
import { CollateralService, MarginAccountStatus } from './collateral.service';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class LiquidationService {
  private readonly logger = new Logger(LiquidationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly oracle: OracleService,
    private readonly collateralService: CollateralService,
  ) {}

  /**
   * Monitor all accounts for liquidation risk
   * Runs every 5 minutes
   */
  @Cron(CronExpression.EVERY_5_MINUTES)
  async monitorAccounts() {
    this.logger.log('Monitoring accounts for liquidation risk...');
    
    const accountsAtRisk = await this.prisma.marginAccount.findMany({
      where: {
        OR: [
          { status: MarginAccountStatus.MARGIN_CALL },
          { status: MarginAccountStatus.LIQUIDATION_PENDING },
          { ltvRatio: { gte: 0.8 } }
        ]
      },
      include: { user: true }
    });

    for (const account of accountsAtRisk) {
      const health = await this.collateralService.calculateAccountHealth(account.userId);
      
      if (health.status === MarginAccountStatus.LIQUIDATION_PENDING) {
        this.logger.warn(`Account ${account.userId} is eligible for liquidation. LTV: ${(Number(health.ltvRatio) * 100).toFixed(2)}%`);
        await this.liquidateAccount(account.userId, 'SYSTEM_LIQUIDATOR');
      } else if (health.status === MarginAccountStatus.MARGIN_CALL) {
        this.logger.log(`Account ${account.userId} is in margin call. LTV: ${(Number(health.ltvRatio) * 100).toFixed(2)}%`);
        // Here we would typically send a notification (e.g., via NotificationService)
      }
    }
  }

  /**
   * Perform liquidation on an account
   * @param userId The user ID to liquidate
   * @param liquidatorAddress The address of the liquidator (could be a system address or a user)
   * @param partial If true, only liquidates enough to reach target LTV. If false, liquidates the whole position.
   */
  async liquidateAccount(userId: string, liquidatorAddress: string, partial: boolean = true) {
    const health = await this.collateralService.calculateAccountHealth(userId);
    
    if (health.status !== MarginAccountStatus.LIQUIDATION_PENDING && health.ltvRatio < 0.9) {
      throw new BadRequestException('Account is not eligible for liquidation');
    }

    const marginAccount = await this.prisma.marginAccount.findUnique({
      where: { userId },
      include: {
        pledges: { include: { asset: true } },
        loans: { where: { status: 'ACTIVE' } },
      }
    });

    if (!marginAccount || marginAccount.pledges.length === 0 || marginAccount.loans.length === 0) {
      throw new BadRequestException('Nothing to liquidate');
    }

    // Sort pledges by value descending (liquidate most valuable first)
    const sortedPledges = [...marginAccount.pledges].sort((a, b) => 
      Number(b.lastValuationUsd) - Number(a.lastValuationUsd)
    );

    // Sort loans by amount descending
    const sortedLoans = [...marginAccount.loans].sort((a, b) => 
      Number(b.amount) - Number(a.amount)
    );

    const targetLtv = 0.7; // Aim for 70% LTV after partial liquidation
    let totalValueToLiquidateUsd = Number(health.totalBorrowedUsd);
    
    if (partial) {
      // Amount to liquidate to reach target LTV
      // CurrentBorrowed - Liquidated = TargetLTV * (CurrentCollateral - Liquidated / (1-Fee))
      // For simplicity, let's just liquidate enough to cover 50% of the debt or reach target LTV
      const debtReductionNeeded = Number(health.totalBorrowedUsd) - (Number(health.totalCollateralValueUsd) * targetLtv);
      totalValueToLiquidateUsd = Math.max(debtReductionNeeded, Number(health.totalBorrowedUsd) * 0.2); // Liquidate at least 20%
    }

    let remainingValueToLiquidateUsd = totalValueToLiquidateUsd;
    const liquidationResults = [];

    await this.prisma.$transaction(async (tx) => {
      for (const loan of sortedLoans) {
        if (remainingValueToLiquidateUsd <= 0) break;

        const loanPrice = await this.oracle.getPrice(loan.assetSymbol);
        const loanTotalAmount = Number(loan.amount) + Number(loan.accruedInterest);
        const loanValueUsd = loanTotalAmount * loanPrice;

        const valueToRepayUsd = Math.min(loanValueUsd, remainingValueToLiquidateUsd);
        const amountToRepay = valueToRepayUsd / loanPrice;

        // Find collateral to seize
        let collateralSeizedUsd = 0;
        const seizedAssets = [];

        // Liquidation fee (e.g., 5% bonus to liquidator)
        const liquidationBonus = 1.05; 
        const neededCollateralValueUsd = valueToRepayUsd * liquidationBonus;

        for (const pledge of sortedPledges) {
          if (collateralSeizedUsd >= neededCollateralValueUsd) break;

          const pledgePrice = await this.oracle.getPrice(pledge.assetSymbol);
          const pledgeAmount = Number(pledge.amount);
          const pledgeValueUsd = pledgeAmount * pledgePrice;

          const valueToTakeUsd = Math.min(pledgeValueUsd, neededCollateralValueUsd - collateralSeizedUsd);
          const amountToTake = valueToTakeUsd / pledgePrice;

          await tx.collateralPledge.update({
            where: { id: pledge.id },
            data: { amount: { decrement: amountToTake } }
          });

          collateralSeizedUsd += valueToTakeUsd;
          seizedAssets.push({ symbol: pledge.assetSymbol, amount: amountToTake });
        }

        // Update loan
        if (amountToRepay >= loanTotalAmount) {
          await tx.loan.update({
            where: { id: loan.id },
            data: { status: 'LIQUIDATED', amount: 0, accruedInterest: 0 }
          });
        } else {
          // Subtract from accrued interest first, then principal
          const interestReduction = Math.min(Number(loan.accruedInterest), amountToRepay);
          const principalReduction = amountToRepay - interestReduction;

          await tx.loan.update({
            where: { id: loan.id },
            data: {
              accruedInterest: { decrement: interestReduction },
              amount: { decrement: principalReduction }
            }
          });
        }

        // Record liquidation
        for (const seized of seizedAssets) {
          await tx.liquidation.create({
            data: {
              marginAccountId: marginAccount.id,
              liquidatorAddress,
              collateralSymbol: seized.symbol,
              collateralAmount: seized.amount,
              loanSymbol: loan.assetSymbol,
              loanAmount: amountToRepay,
              liquidationFee: valueToRepayUsd * 0.05, // 5% fee recorded
            }
          });
        }

        remainingValueToLiquidateUsd -= valueToRepayUsd;
        liquidationResults.push({ loan: loan.assetSymbol, amountRepaid: amountToRepay, seizedAssets });
      }
    });

    this.logger.log(`Liquidation completed for user ${userId}. Status: ${partial ? 'Partial' : 'Full'}`);
    
    // Recalculate health after liquidation
    return this.collateralService.calculateAccountHealth(userId);
  }
}
