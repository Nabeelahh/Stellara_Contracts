export class SettlementResultDto {
  instrument: string;
  totalVariation: number;
  settledAt: number;
  details: Array<{ memberId: string; variation: number; drainedDefaultFund?: number }>;
}
