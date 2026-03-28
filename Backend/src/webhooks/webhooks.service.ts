import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { CircuitBreakerService } from '../circuit-breaker/circuit-breaker.service';
import { PrismaService } from '../prisma.service';
import {
  CreateWebhookSubscriptionDto,
  PublishWebhookEventDto,
  UpdateWebhookSubscriptionDto,
} from './dto/webhook.dto';

type DeliveryStatus = 'PENDING' | 'RETRYING' | 'DELIVERED' | 'FAILED';

const MAX_ATTEMPTS = 10;
const DEFAULT_TIMEOUT_MS = 10000;
const BASE_RETRY_DELAY_MS = 60_000;

@Injectable()
export class WebhooksService {
  private readonly logger = new Logger(WebhooksService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly circuitBreakerService: CircuitBreakerService,
  ) {
    this.circuitBreakerService.register('external-webhooks', {
      failureThreshold: 5,
      failureWindowMs: 10_000,
      openTimeoutMs: 30_000,
      halfOpenMaxCalls: 10,
      halfOpenSuccessThreshold: 3,
    });
  }

  async createSubscription(dto: CreateWebhookSubscriptionDto, actorId?: string) {
    return (this.prisma as any).webhookSubscription.create({
      data: {
        name: dto.name,
        description: dto.description,
        url: dto.url,
        secret: dto.secret,
        status: dto.status ?? 'ACTIVE',
        eventFilters: dto.eventFilters,
        payloadFields: dto.payloadFields ?? null,
        customHeaders: dto.customHeaders ?? null,
        tenantId: dto.tenantId ?? null,
        createdBy: actorId ?? null,
      },
    });
  }

  async listSubscriptions(tenantId?: string) {
    return (this.prisma as any).webhookSubscription.findMany({
      where: tenantId ? { tenantId } : {},
      orderBy: { createdAt: 'desc' },
    });
  }

  async getSubscription(id: string) {
    const subscription = await (this.prisma as any).webhookSubscription.findUnique({
      where: { id },
    });

    if (!subscription) {
      throw new NotFoundException(`Webhook subscription ${id} not found`);
    }

    return subscription;
  }

  async updateSubscription(id: string, dto: UpdateWebhookSubscriptionDto) {
    await this.getSubscription(id);

    return (this.prisma as any).webhookSubscription.update({
      where: { id },
      data: {
        ...(dto.name !== undefined ? { name: dto.name } : {}),
        ...(dto.description !== undefined ? { description: dto.description } : {}),
        ...(dto.url !== undefined ? { url: dto.url } : {}),
        ...(dto.secret !== undefined ? { secret: dto.secret } : {}),
        ...(dto.status !== undefined ? { status: dto.status } : {}),
        ...(dto.eventFilters !== undefined ? { eventFilters: dto.eventFilters } : {}),
        ...(dto.payloadFields !== undefined ? { payloadFields: dto.payloadFields } : {}),
        ...(dto.customHeaders !== undefined ? { customHeaders: dto.customHeaders } : {}),
      },
    });
  }

  async deleteSubscription(id: string) {
    await this.getSubscription(id);
    await (this.prisma as any).webhookSubscription.delete({
      where: { id },
    });

    return { success: true };
  }

  async publishEvent(dto: PublishWebhookEventDto) {
    const matchingSubscriptions = await this.findMatchingSubscriptions(dto.eventType, dto.tenantId);

    const event = await (this.prisma as any).webhookEvent.create({
      data: {
        eventType: dto.eventType,
        payload: dto.payload,
        metadata: dto.metadata ?? null,
        source: dto.source ?? 'platform',
        tenantId: dto.tenantId ?? null,
      },
    });

    if (matchingSubscriptions.length === 0) {
      return {
        event,
        deliveriesCreated: 0,
      };
    }

    const deliveries = await Promise.all(
      matchingSubscriptions.map((subscription) =>
        (this.prisma as any).webhookDelivery.create({
          data: {
            subscriptionId: subscription.id,
            eventId: event.id,
            status: 'PENDING',
            attempts: 0,
            maxAttempts: MAX_ATTEMPTS,
            nextAttemptAt: new Date(),
          },
        }),
      ),
    );

    await Promise.all(deliveries.map((delivery) => this.processDeliveryById(delivery.id)));

    return {
      event,
      deliveriesCreated: deliveries.length,
    };
  }

  async sendTestWebhook(subscriptionId: string) {
    const subscription = await this.getSubscription(subscriptionId);
    const tenantId = subscription.tenantId ?? undefined;

    return this.publishEvent({
      eventType: 'webhook.test',
      source: 'dashboard',
      tenantId,
      metadata: {
        subscriptionId,
        test: true,
      },
      payload: {
        message: 'This is a test webhook delivery from Stellara.',
        subscriptionId,
        emittedAt: new Date().toISOString(),
      },
    });
  }

  async getDashboard(tenantId?: string) {
    const [subscriptions, deliveries] = await Promise.all([
      (this.prisma as any).webhookSubscription.findMany({
        where: tenantId ? { tenantId } : {},
      }),
      (this.prisma as any).webhookDelivery.findMany({
        where: tenantId ? { subscription: { tenantId } } : {},
        include: {
          subscription: {
            select: {
              id: true,
              name: true,
            },
          },
          event: {
            select: {
              id: true,
              eventType: true,
              occurredAt: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
        take: 200,
      }),
    ]);

    const deliveriesByStatus = deliveries.reduce<Record<string, number>>((acc, delivery) => {
      acc[delivery.status] = (acc[delivery.status] ?? 0) + 1;
      return acc;
    }, {});

    const failures = deliveries.filter((delivery) => delivery.status === 'FAILED').slice(0, 20);

    return {
      subscriptions: {
        total: subscriptions.length,
        active: subscriptions.filter((subscription) => subscription.status === 'ACTIVE').length,
        paused: subscriptions.filter((subscription) => subscription.status === 'PAUSED').length,
        disabled: subscriptions.filter((subscription) => subscription.status === 'DISABLED').length,
      },
      deliveries: {
        total: deliveries.length,
        byStatus: deliveriesByStatus,
        successRate:
          deliveries.length === 0
            ? 0
            : Number(
                (
                  (deliveries.filter((delivery) => delivery.status === 'DELIVERED').length /
                    deliveries.length) *
                  100
                ).toFixed(2),
              ),
      },
      recentFailures: failures,
    };
  }

  async listDeliveries(filters: {
    status?: DeliveryStatus;
    subscriptionId?: string;
    tenantId?: string;
  }) {
    return (this.prisma as any).webhookDelivery.findMany({
      where: {
        ...(filters.status ? { status: filters.status } : {}),
        ...(filters.subscriptionId ? { subscriptionId: filters.subscriptionId } : {}),
        ...(filters.tenantId ? { subscription: { tenantId: filters.tenantId } } : {}),
      },
      include: {
        subscription: true,
        event: true,
      },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });
  }

  async retryDelivery(id: string) {
    const delivery = await (this.prisma as any).webhookDelivery.findUnique({
      where: { id },
    });

    if (!delivery) {
      throw new NotFoundException(`Webhook delivery ${id} not found`);
    }

    await (this.prisma as any).webhookDelivery.update({
      where: { id },
      data: {
        status: 'PENDING',
        attempts: 0,
        nextAttemptAt: new Date(),
        errorMessage: null,
        lastResponseBody: null,
        lastResponseCode: null,
      },
    });

    return this.processDeliveryById(id);
  }

  async processDueDeliveries(limit = 50) {
    const deliveries = await (this.prisma as any).webhookDelivery.findMany({
      where: {
        status: { in: ['PENDING', 'RETRYING'] },
        nextAttemptAt: { lte: new Date() },
        attempts: { lt: MAX_ATTEMPTS },
      },
      orderBy: { nextAttemptAt: 'asc' },
      take: limit,
    });

    for (const delivery of deliveries) {
      await this.processDeliveryById(delivery.id);
    }

    return deliveries.length;
  }

  private async processDeliveryById(id: string) {
    const delivery = await (this.prisma as any).webhookDelivery.findUnique({
      where: { id },
      include: {
        subscription: true,
        event: true,
      },
    });

    if (!delivery) {
      throw new NotFoundException(`Webhook delivery ${id} not found`);
    }

    if (delivery.subscription.status !== 'ACTIVE') {
      return delivery;
    }

    const payload = this.buildPayload(delivery.subscription, delivery.event);
    const body = JSON.stringify(payload);
    const timestamp = `${Date.now()}`;
    const signature = this.signPayload(delivery.subscription.secret, timestamp, body);
    const attemptNumber = delivery.attempts + 1;
    const timeoutMs = this.resolveTimeoutMs();

    try {
      const response = await this.circuitBreakerService.execute('external-webhooks', () =>
        fetch(delivery.subscription.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Stellara-Webhooks/1.0',
            'X-Stellara-Event': delivery.event.eventType,
            'X-Stellara-Delivery': delivery.id,
            'X-Stellara-Attempt': `${attemptNumber}`,
            'X-Stellara-Timestamp': timestamp,
            'X-Stellara-Signature': signature,
            ...this.normalizeHeaders(delivery.subscription.customHeaders),
          },
          body,
          signal: AbortSignal.timeout(timeoutMs),
        }),
      );

      const responseBody = await response.text();
      const success = response.status >= 200 && response.status < 300;

      await (this.prisma as any).webhookSubscription.update({
        where: { id: delivery.subscriptionId },
        data: {
          lastTriggeredAt: new Date(),
        },
      });

      if (success) {
        await (this.prisma as any).webhookDelivery.update({
          where: { id: delivery.id },
          data: {
            status: 'DELIVERED',
            attempts: attemptNumber,
            deliveredAt: new Date(),
            lastAttemptAt: new Date(),
            lastResponseCode: response.status,
            lastResponseBody: responseBody.slice(0, 4000),
            errorMessage: null,
            signature,
          },
        });

        return {
          id: delivery.id,
          status: 'DELIVERED',
        };
      }

      throw new Error(`Webhook endpoint returned status ${response.status}: ${responseBody}`);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Webhook delivery failed';
      this.logger.error(
        `Webhook delivery ${delivery.id} failed on attempt ${attemptNumber}: ${message}`,
      );

      const finalAttempt = attemptNumber >= MAX_ATTEMPTS;
      await (this.prisma as any).webhookDelivery.update({
        where: { id: delivery.id },
        data: {
          status: finalAttempt ? 'FAILED' : 'RETRYING',
          attempts: attemptNumber,
          lastAttemptAt: new Date(),
          errorMessage: message.slice(0, 1000),
          nextAttemptAt: this.calculateNextAttemptAt(attemptNumber),
          signature,
        },
      });

      return {
        id: delivery.id,
        status: finalAttempt ? 'FAILED' : 'RETRYING',
      };
    }
  }

  private async findMatchingSubscriptions(eventType: string, tenantId?: string) {
    const subscriptions = await (this.prisma as any).webhookSubscription.findMany({
      where: {
        status: 'ACTIVE',
        ...(tenantId ? { OR: [{ tenantId }, { tenantId: null }] } : {}),
      },
    });

    return subscriptions.filter((subscription) =>
      this.matchesFilter(subscription.eventFilters ?? [], eventType),
    );
  }

  private matchesFilter(filters: string[], eventType: string): boolean {
    return filters.some((filter) => {
      if (filter === '*' || filter === eventType) {
        return true;
      }

      if (filter.endsWith('*')) {
        return eventType.startsWith(filter.slice(0, -1));
      }

      return false;
    });
  }

  private buildPayload(subscription: any, event: any) {
    const selectedPayload =
      Array.isArray(subscription.payloadFields) && subscription.payloadFields.length > 0
        ? this.pickPaths(event.payload, subscription.payloadFields)
        : event.payload;

    return {
      id: event.id,
      type: event.eventType,
      source: event.source,
      occurredAt: event.occurredAt,
      subscriptionId: subscription.id,
      payload: selectedPayload,
      metadata: event.metadata ?? {},
    };
  }

  private pickPaths(source: Record<string, any>, paths: string[]) {
    const result: Record<string, unknown> = {};

    for (const path of paths) {
      const value = this.getPathValue(source, path);
      if (value === undefined) {
        continue;
      }

      this.setPathValue(result, path, value);
    }

    return result;
  }

  private getPathValue(source: Record<string, any>, path: string) {
    return path.split('.').reduce((current, part) => current?.[part], source);
  }

  private setPathValue(target: Record<string, unknown>, path: string, value: unknown) {
    const parts = path.split('.');
    let cursor: Record<string, any> = target;

    parts.forEach((part, index) => {
      if (index === parts.length - 1) {
        cursor[part] = value;
        return;
      }

      if (!cursor[part] || typeof cursor[part] !== 'object') {
        cursor[part] = {};
      }

      cursor = cursor[part] as Record<string, any>;
    });
  }

  private signPayload(secret: string, timestamp: string, body: string) {
    return createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  }

  verifySignature(secret: string, timestamp: string, body: string, signature: string) {
    const expected = this.signPayload(secret, timestamp, body);
    const expectedBuffer = Buffer.from(expected);
    const signatureBuffer = Buffer.from(signature);

    if (expectedBuffer.length !== signatureBuffer.length) {
      return false;
    }

    return timingSafeEqual(expectedBuffer, signatureBuffer);
  }

  private normalizeHeaders(headers: Record<string, string> | null | undefined) {
    if (!headers || typeof headers !== 'object') {
      return {};
    }

    return Object.entries(headers).reduce<Record<string, string>>((acc, [key, value]) => {
      if (typeof value === 'string' && !key.toLowerCase().startsWith('x-stellara-')) {
        acc[key] = value;
      }
      return acc;
    }, {});
  }

  private calculateNextAttemptAt(attempts: number) {
    const multiplier = Math.pow(2, Math.max(0, attempts - 1));
    const delay = Math.min(BASE_RETRY_DELAY_MS * multiplier, 9 * 60 * 60 * 1000);
    return new Date(Date.now() + delay);
  }

  private resolveTimeoutMs() {
    const raw = Number(process.env.WEBHOOK_REQUEST_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS);
    return Number.isNaN(raw) ? DEFAULT_TIMEOUT_MS : raw;
  }
}
