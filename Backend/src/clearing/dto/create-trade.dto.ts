export class CreateTradeDto {
  // Unique trade id from matching engine
  tradeId: string;
  // Clearing member identifiers (buyer/seller)
  buyerId: string;
  sellerId: string;
  // Instrument (symbol), e.g., BTC-USD-2026-06-30-FUT
  instrument: string;
  // Notional size (positive number)
  notional: number;
  // Price agreed
  price: number;
  // Trade timestamp (ms since epoch)
  timestamp?: number;
}
