import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { ScorePaymentDto, ScoreResult } from './dto/score-payment.dto';
import { PaymentEventType } from '@prisma/client';

// Use global fetch if available (Node 18+). This allows calling an external model server
// when `FRAUD_SCORER_URL` is configured. If the remote call fails, fall back to local heuristic.
declare const fetch: any;

@Injectable()
export class FraudService {
  private readonly logger = new Logger(FraudService.name);

  // Lightweight disposable domains list for quick checks
  private disposableDomains = new Set([
    'mailinator.com',
    'dispostable.com',
    '10minutemail.com',
    'tempmail.com',
  ]);

  constructor(private readonly prisma: PrismaService) {}

  // Synchronous fast heuristic + quick DB-backed signals where available
  async scorePayment(input: ScorePaymentDto): Promise<ScoreResult> {
    // If a remote scorer is configured, prefer it for ensemble/GNN models.
    const remote = process.env.FRAUD_SCORER_URL;
    if (remote) {
      try {
        const u = remote.replace(/\/$/, '');
        const res = await fetch(u + '/score', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(input),
          // keep short timeout behaviour to avoid hanging the payment flow (caller can set timeout)
        });
        if (res && res.ok) {
          const data = await res.json();
          // basic validation
          if (typeof data.score === 'number' && data.action) {
            return data as ScoreResult;
          }
        } else {
          this.logger.warn(`Remote scorer returned non-OK: ${res?.status}`);
        }
      } catch (err) {
        this.logger.warn('Remote fraud scorer call failed: ' + (err?.message || err));
      }
    }

    // Local lightweight fallback (heuristic + DB signals)
    const reasons: string[] = [];
    let score = 0;

    try {
      const parts = (input.email || '').split('@');
      const domain = parts.length > 1 ? parts[1].toLowerCase() : '';
      if (this.disposableDomains.has(domain)) {
        score += 0.6;
        reasons.push('disposable_email_domain');
      }
    } catch (e) {
      // ignore
    }

    if (input.isNewTenant) {
      score += 0.08;
      reasons.push('new_tenant');
    }

    if (!input.paymentMethodId) {
      score += 0.05;
      reasons.push('no_payment_method');
    }

    try {
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const failedCount = await this.prisma.paymentEvent.count({
        where: {
          tenantId: input.tenantId,
          eventType: PaymentEventType.PAYMENT_FAILED,
          createdAt: { gte: since },
        },
      });
      if (failedCount > 0) {
        const add = Math.min(0.2, 0.06 * failedCount);
        score += add;
        reasons.push(`recent_failed_payments:${failedCount}`);
      }
    } catch (e) {
      this.logger.debug('Prisma check for recent failures failed: ' + e?.message);
    }

    score = Math.max(0, Math.min(1, score));

    let action: ScoreResult['action'] = 'allow';
    if (score >= 0.7) action = 'block';
    else if (score >= 0.35) action = 'challenge';

    return { score, action, reasons };
  }
}
