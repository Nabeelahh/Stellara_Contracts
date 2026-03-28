import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';

export enum ManipulationPattern {
  WASH_TRADING = 'WASH_TRADING',
  SPOOFING = 'SPOOFING',
  LAYERING = 'LAYERING',
  PUMP_AND_DUMP = 'PUMP_AND_DUMP',
  UNUSUAL_VOLUME = 'UNUSUAL_VOLUME',
}

export interface SurveillanceAlert {
  pattern: ManipulationPattern;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  entityId: string; // userId or orderId
  description: string;
  metadata: any;
  timestamp: Date;
}

@Injectable()
export class MarketSurveillanceService {
  private readonly logger = new Logger(MarketSurveillanceService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Detects wash trades (self-matching)
   */
  async detectWashTrading(trade: {
    buyerId: string;
    sellerId: string;
    asset: string;
    amount: string;
    price: string;
  }): Promise<SurveillanceAlert | null> {
    if (trade.buyerId === trade.sellerId) {
      return {
        pattern: ManipulationPattern.WASH_TRADING,
        severity: 'HIGH',
        entityId: trade.buyerId,
        description: `Self-matching trade detected for asset ${trade.asset}`,
        metadata: trade,
        timestamp: new Date(),
      };
    }
    // TODO: Detect related addresses (e.g., same IP, same funded source)
    return null;
  }

  /**
   * Detects spoofing (large orders canceled before execution)
   */
  async detectSpoofing(order: {
    userId: string;
    orderId: string;
    asset: string;
    amount: string;
    price: string;
    action: 'CANCEL';
    durationSeconds: number;
  }): Promise<SurveillanceAlert | null> {
    // Basic heuristic: large order canceled within a very short time (e.g., < 5s)
    const LARGE_ORDER_THRESHOLD = 100000; // Example
    const SHORT_DURATION_THRESHOLD = 5;

    if (
      parseFloat(order.amount) > LARGE_ORDER_THRESHOLD &&
      order.durationSeconds < SHORT_DURATION_THRESHOLD
    ) {
      return {
        pattern: ManipulationPattern.SPOOFING,
        severity: 'MEDIUM',
        entityId: order.userId,
        description: `Potential spoofing: large order ${order.orderId} canceled after ${order.durationSeconds}s`,
        metadata: order,
        timestamp: new Date(),
      };
    }
    return null;
  }

  /**
   * Detects layering (multiple price levels)
   */
  async detectLayering(userId: string, activeOrders: any[]): Promise<SurveillanceAlert | null> {
    // Detect multiple small orders at different price levels to simulate depth
    const priceLevels = new Set(activeOrders.map((o) => o.price)).size;
    if (activeOrders.length > 10 && priceLevels >= 5) {
      return {
        pattern: ManipulationPattern.LAYERING,
        severity: 'MEDIUM',
        entityId: userId,
        description: `Layering detected: user has ${activeOrders.length} orders across ${priceLevels} price levels`,
        metadata: { orderCount: activeOrders.length, priceLevels },
        timestamp: new Date(),
      };
    }
    return null;
  }

  /**
   * Detects unusual volume/price correlation (Pump and Dump)
   */
  async detectPumpAndDump(asset: string, windowMinutes: number = 60): Promise<SurveillanceAlert | null> {
    // In a real system, this would query aggregated time-series data
    // Mocking the detection logic
    return null;
  }

  /**
   * Main entry point for surveillance
   */
  async monitorTransaction(data: any): Promise<SurveillanceAlert[]> {
    const alerts: SurveillanceAlert[] = [];
    
    // Run all detectors
    const washAlert = await this.detectWashTrading(data);
    if (washAlert) alerts.push(washAlert);

    // ... other checks ...

    if (alerts.length > 0) {
      this.logger.warn(`Surveillance alerts triggered for entity ${data.buyerId || data.userId}: ${alerts.length}`);
      // Save to DB or notify compliance team
    }

    return alerts;
  }
}
