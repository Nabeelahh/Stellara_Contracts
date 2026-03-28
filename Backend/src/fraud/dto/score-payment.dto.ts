export interface ScorePaymentDto {
  tenantId: string;
  email: string;
  paymentMethodId?: string | null;
  planId?: string | null;
  isNewTenant?: boolean;
  ip?: string | null;
  userAgent?: string | null;
  amount?: number | null;
}

export interface ScoreResult {
  score: number; // 0..1
  action: 'allow' | 'challenge' | 'block';
  reasons: string[];
}
