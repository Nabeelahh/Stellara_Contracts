export interface PositionDto {
  positionId: string;
  memberId: string;
  instrument: string;
  // positive = long, negative = short
  quantity: number;
  avgPrice: number;
  // mark-to-market PnL since last settlement
  unrealizedPnl?: number;
}
