import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { CreateTradeDto } from './dto/create-trade.dto';
import { PositionDto } from './dto/position.dto';
import { SettlementResultDto } from './dto/settlement.dto';

/**
 * ClearingService
 * - Acts as central counterparty: mirrors trades to maintain CCP exposures
 * - Tracks member margins (initial + variation) and a mutualized default fund
 * - Performs daily mark-to-market settlement and default waterfall handling
 *
 * NOTE: This is a high-level implementation scaffold. Production must:
 * - Persist positions and balances in DB (Prisma schema + migrations)
 * - Use deterministic, auditable margin models (SPAN/ISDA SIMM) and stress tests
 * - Integrate with settlement rails (payments, token transfers, on-chain or custodial)
 */

@Injectable()
export class ClearingService {
  private readonly logger = new Logger(ClearingService.name);

  // In-memory stores (replace with DB-backed persistence)
  private positions: Map<string, PositionDto> = new Map();
  private memberMargins: Map<string, { initial: number; variation: number; balance: number }> =
    new Map();
  private defaultFund: { total: number; contributions: Map<string, number> } = {
    total: 0,
    contributions: new Map(),
  };

  constructor(private readonly prisma: PrismaService) {}

  // Accept trade from matching engine, record mirrored positions so CCP is counterparty
  async acceptTrade(trade: CreateTradeDto) {
    // Create/adjust buyer long position
    const buyPosId = `${trade.tradeId}:buy`;
    const sellPosId = `${trade.tradeId}:sell`;

    const buyerPos: PositionDto = {
      positionId: buyPosId,
      memberId: trade.buyerId,
      instrument: trade.instrument,
      quantity: trade.notional, // for simple futures notation
      avgPrice: trade.price,
      unrealizedPnl: 0,
    };

    const sellerPos: PositionDto = {
      positionId: sellPosId,
      memberId: trade.sellerId,
      instrument: trade.instrument,
      quantity: -trade.notional,
      avgPrice: trade.price,
      unrealizedPnl: 0,
    };

    // Persist positions (DB-backed via Prisma)
    try {
      await this.prisma.clearingPosition.create({
        data: {
          tradeId: trade.tradeId,
          memberId: trade.buyerId,
          instrument: trade.instrument,
          quantity: trade.notional,
          avgPrice: trade.price,
        },
      });
      await this.prisma.clearingPosition.create({
        data: {
          tradeId: trade.tradeId,
          memberId: trade.sellerId,
          instrument: trade.instrument,
          quantity: -trade.notional,
          avgPrice: trade.price,
        },
      });
    } catch (e) {
      this.logger.error('Failed to persist clearing positions: ' + (e?.message || e));
    }

    // keep in-memory for quick access as well
    this.positions.set(buyPosId, buyerPos);
    this.positions.set(sellPosId, sellerPos);

    // Ensure margin accounts exist (DB upsert)
    try {
      await this.prisma.clearingMarginAccount.upsert({
        where: { memberId: trade.buyerId },
        create: { memberId: trade.buyerId, initial: 0, variation: 0, balance: 0 },
        update: {},
      });
      await this.prisma.clearingMarginAccount.upsert({
        where: { memberId: trade.sellerId },
        create: { memberId: trade.sellerId, initial: 0, variation: 0, balance: 0 },
        update: {},
      });
    } catch (e) {
      this.logger.debug('Prisma upsert margin account failed: ' + (e?.message || e));
    }
    this.ensureMemberAccount(trade.buyerId);
    this.ensureMemberAccount(trade.sellerId);

    // Compute initial margin requirements for both sides and reserve balances
    const imBuyer = this.calculateInitialMargin(buyerPos);
    const imSeller = this.calculateInitialMargin(sellerPos);

    this.reserveInitialMargin(trade.buyerId, imBuyer);
    this.reserveInitialMargin(trade.sellerId, imSeller);

    // Persist margin reservation to DB (basic reflection)
    try {
      await this.prisma.clearingMarginAccount.update({
        where: { memberId: trade.buyerId },
        data: {
          initial: { increment: imBuyer },
          balance: { decrement: imBuyer },
        },
      });
      await this.prisma.clearingMarginAccount.update({
        where: { memberId: trade.sellerId },
        data: {
          initial: { increment: imSeller },
          balance: { decrement: imSeller },
        },
      });
    } catch (e) {
      this.logger.debug('Failed to persist margin reservation: ' + (e?.message || e));
    }

    this.logger.log(`Accepted trade ${trade.tradeId}, IM reserved buyer:${imBuyer} seller:${imSeller}`);
    return { buyPosId, sellPosId, imBuyer, imSeller };
  }

  private ensureMemberAccount(memberId: string) {
    if (!this.memberMargins.has(memberId)) {
      this.memberMargins.set(memberId, { initial: 0, variation: 0, balance: 0 });
    }
  }

  // Placeholder: compute initial margin based on notional and instrument volatility profile
  calculateInitialMargin(pos: PositionDto): number {
    // Simple percent-of-notional model for prototype
    const pct = 0.05; // 5% initial margin
    return Math.abs(pos.quantity * pos.avgPrice) * pct;
  }

  reserveInitialMargin(memberId: string, amount: number) {
    const acct = this.memberMargins.get(memberId)!;
    acct.initial += amount;
    acct.balance -= amount; // reserved; negative balance means collateral held
    this.memberMargins.set(memberId, acct);
  }

  // Mark-to-market settlement: compute variation margins based on market price
  async settleMarkToMarket(instrument: string, marketPrice: number): Promise<SettlementResultDto> {
    const details: Array<{ memberId: string; variation: number; drainedDefaultFund?: number }> = [];
    let totalVariation = 0;

    for (const pos of this.positions.values()) {
      if (pos.instrument !== instrument) continue;
      const old = pos.unrealizedPnl || 0;
      const newPnl = (pos.quantity) * (marketPrice - pos.avgPrice);
      const variation = newPnl - old;
      pos.unrealizedPnl = newPnl;

      // Apply variation to member margin accounts; negative variation implies they owe funds
      const acct = this.memberMargins.get(pos.memberId)!;
      acct.variation += variation;
      acct.balance -= variation;
      this.memberMargins.set(pos.memberId, acct);

      // persist variation and balance to DB
      try {
        await this.prisma.clearingMarginAccount.update({
          where: { memberId: pos.memberId },
          data: {
            variation: { increment: variation },
            balance: variation < 0 ? { decrement: Math.abs(variation) } : { increment: variation },
          },
        });
      } catch (e) {
        this.logger.debug('Failed to persist variation for member ' + pos.memberId + ': ' + (e?.message || e));
      }

      // Check for breach: if balance < -initialMargin, member default
      const breached = acct.balance < -acct.initial;
      let drained = 0;
      if (breached) {
        // Trigger default handling for this member
        drained = this.handleDefault(pos.memberId, Math.abs(acct.balance));
      }

      details.push({ memberId: pos.memberId, variation, drainedDefaultFund: drained });
      totalVariation += variation;
    }

    const result: SettlementResultDto = {
      instrument,
      totalVariation,
      settledAt: Date.now(),
      details,
    };

    // Persist settlement summary
    try {
      await this.prisma.clearingSettlement.create({
        data: {
          instrument,
          totalVariation: totalVariation,
          details: JSON.stringify(details),
          settledAt: new Date(result.settledAt),
        },
      });
    } catch (e) {
      this.logger.debug('Failed to persist settlement record: ' + (e?.message || e));
    }

    this.logger.log(`MTM settled instrument=${instrument} price=${marketPrice} totalVariation=${totalVariation}`);
    return result;
  }

  // Default waterfall: attempt to absorb shortfall from defaulter margins, then default fund, then mutualized loss
  private handleDefault(defaulterId: string, shortfall: number): number {
    this.logger.warn(`Member default detected: ${defaulterId} shortfall=${shortfall}`);
    // 1) Use defaulter's remaining initial margin (already negative balance)
    const acct = this.memberMargins.get(defaulterId)!;
    const usedFromDefaulter = Math.min(shortfall, Math.max(0, acct.initial + acct.balance * -1));
    shortfall -= usedFromDefaulter;

    // 2) Use default fund pool proportionally
    let drainedFromDefault = 0;
    if (shortfall > 0 && this.defaultFund.total > 0) {
      // Each member contributes proportionally; for simplicity, drain up to defaultFund.total
      const avail = this.defaultFund.total;
      const drain = Math.min(avail, shortfall);
      this.defaultFund.total -= drain;
      drainedFromDefault = drain;
      shortfall -= drain;
    }

    // 3) Mutualized loss: distribute remaining shortfall across surviving members by contribution share
    if (shortfall > 0) {
      // compute total contributions
      const totalContrib = Array.from(this.defaultFund.contributions.values()).reduce((a, b) => a + b, 0);
      if (totalContrib > 0) {
        for (const [memberId, contrib] of this.defaultFund.contributions.entries()) {
          const share = contrib / totalContrib;
          const take = share * shortfall;
          // deduct from member balances (mutualized)
          const mAcct = this.memberMargins.get(memberId);
          if (mAcct) {
            mAcct.balance -= take;
            this.memberMargins.set(memberId, mAcct);
          }
        }
        shortfall = 0;
      } else {
        // No contributors: system loss remains (requires recovery powers)
        this.logger.error('Mutualized loss could not be applied — insufficient default fund contributions');
      }
    }

    return drainedFromDefault + usedFromDefaulter;
  }

  // Members contribute to default fund proportionally; record contributions
  contributeDefaultFund(memberId: string, amount: number) {
    if (amount <= 0) return;
    const prev = this.defaultFund.contributions.get(memberId) || 0;
    this.defaultFund.contributions.set(memberId, prev + amount);
    this.defaultFund.total += amount;

    // reflect on member account
    this.ensureMemberAccount(memberId);
    const acct = this.memberMargins.get(memberId)!;
    acct.balance -= amount; // contribution paid out of balance
    this.memberMargins.set(memberId, acct);
    this.logger.log(`Member ${memberId} contributed ${amount} to default fund`);
    // persist contribution
    try {
      this.prisma.defaultFundContribution.create({
        data: { memberId, amount },
      });
    } catch (e) {
      this.logger.debug('Failed to persist default fund contribution: ' + (e?.message || e));
    }
  }

  // Auction process placeholder for liquidating collateral/positions of defaulted member
  async startAuctionForDefault(defaulterId: string) {
    // In production: create auction lot, notify market participants, accept bids, transfer positions
    this.logger.log(`Starting auction for defaulted member ${defaulterId}`);
    try {
      const rec = await this.prisma.clearingAuction.create({
        data: { defaulterId, status: 'OPEN' },
      });
      return { auctionId: rec.id };
    } catch (e) {
      this.logger.debug('Failed to create auction record: ' + (e?.message || e));
      return { auctionId: `auction:${defaulterId}:${Date.now()}` };
    }
  }

  // Recovery / orderly termination powers: placeholder to mark system-level actions
  async triggerRecovery(reason: string) {
    this.logger.warn(`Recovery procedure triggered: ${reason}`);
    // Implement governance hooks, pause new trades, wind-down procedures
    return { status: 'recovery_started', reason };
  }

  // Utility: get member margins (for reporting)
  getMemberMargin(memberId: string) {
    return this.memberMargins.get(memberId) || { initial: 0, variation: 0, balance: 0 };
  }

  // Utility: get default fund status
  getDefaultFund() {
    return { total: this.defaultFund.total, contributions: Array.from(this.defaultFund.contributions.entries()) };
  }
}
