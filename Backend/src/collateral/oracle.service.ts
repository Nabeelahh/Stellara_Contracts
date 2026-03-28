import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class OracleService {
  private readonly logger = new Logger(OracleService.name);
  
  // Mock prices for now. In a real scenario, this would fetch from an external API or on-chain oracle.
  private readonly mockPrices: Record<string, number> = {
    'XLM': 0.12,
    'BTC': 65000,
    'ETH': 3500,
    'USDC': 1.0,
    'USDT': 1.0,
  };

  async getPrice(symbol: string): Promise<number> {
    const price = this.mockPrices[symbol.toUpperCase()];
    if (price === undefined) {
      this.logger.warn(`Price not found for asset: ${symbol}`);
      return 0;
    }
    return price;
  }

  async getAllPrices(): Promise<Record<string, number>> {
    return { ...this.mockPrices };
  }
}
