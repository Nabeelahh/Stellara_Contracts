import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { ConsumeMessage } from 'amqplib';
import { RabbitMqService } from './rabbitmq.service';
import {
  dlqQueueName,
  EVENT_DOMAIN,
  mainQueueName,
  MAX_RETRIES,
  type RabbitMqDomain,
} from './rabbitmq.constants';
import type { BusEnvelope, EventName } from './rabbitmq.types';
import { RedisService } from '../../redis/redis.service';
import { PrismaService } from '../../prisma.service';
import { Cron } from '@nestjs/schedule';
import { NotificationService } from '../../notification/services/notification.service';
import { NotificationType } from '@prisma/client';
import { setTimeout as delay } from 'node:timers/promises';

const processedKey = (eventId: string) => `bus:processed:${eventId}`;

@Injectable()
export class RabbitMqConsumerService implements OnModuleInit {
  private readonly logger = new Logger(RabbitMqConsumerService.name);

  constructor(
    private readonly rabbit: RabbitMqService,
    private readonly redis: RedisService,
    private readonly prisma: PrismaService,
    private readonly notificationService: NotificationService,
  ) {}

  async onModuleInit(): Promise<void> {
    const channel = this.rabbit.getChannel();
    const events: string[] = Object.keys(EVENT_DOMAIN);

    for (const eventName of events) {
      const domain = EVENT_DOMAIN[eventName];
      const queue = mainQueueName(domain, eventName);
      await channel.prefetch(10);

      await channel.consume(
        queue,
        async (msg) => {
          if (!msg) return;
          await this.handleMessage(msg, domain, eventName);
        },
        { noAck: false },
      );
    }
  }

  private async handleMessage(msg: ConsumeMessage, domain: any, eventName: string): Promise<void> {
    const envelope = this.parseEnvelope(msg);
    const eventId = String(envelope.eventId);
    const attempt = Number(envelope.attempt ?? msg.properties.headers?.['x-attempt'] ?? 0);
    const redis = this.redis.getClient();

    const already = await redis.get(processedKey(eventId));
    if (already) return this.rabbit.getChannel().ack(msg);

    try {
      // Route to specific handler.
      await this.handleEvent(domain, envelope);

      // Mark processed only after successful handler execution.
      await redis.set(processedKey(eventId), '1', 'NX', 'EX', 7 * 24 * 60 * 60);
      this.rabbit.getChannel().ack(msg);
    } catch (err) {
      const nextAttempt = attempt + 1;
      // Retry queues exist for attempts `1..MAX_RETRIES-1`.
      // When `nextAttempt` reaches `MAX_RETRIES`, route to DLQ.
      if (nextAttempt >= MAX_RETRIES) {
        // Move to DLQ.
        const dlqEnvelope = { ...envelope, attempt };
        await this.rabbit.publishToDlq(domain, eventName, dlqEnvelope);
        this.rabbit.getChannel().ack(msg);
        return;
      }

      // Retry by publishing to delay queue.
      await this.rabbit.publishToRetry(
        domain,
        eventName,
        { ...envelope, attempt: nextAttempt },
        nextAttempt,
      );
      this.rabbit.getChannel().ack(msg);
    }
  }

  private parseEnvelope(msg: ConsumeMessage): BusEnvelope {
    try {
      const raw = msg.content.toString('utf8');
      return JSON.parse(raw) as BusEnvelope;
    } catch {
      // If parsing fails, we DLQ immediately.
      return {
        eventId: 'invalid',
        eventName: 'UserCreated',
        occurredAt: new Date().toISOString(),
        payload: {},
        attempt: 0,
      };
    }
  }

  private async handleEvent(domain: string, envelope: BusEnvelope): Promise<void> {
    // TODO: Replace these no-ops with real domain logic.
    this.logger.log(
      `Handling event ${envelope.eventName} (domain=${domain}, id=${envelope.eventId})`,
    );
    // Simulate async work.
    await delay(1);
  }

  @Cron('* * * * *')
  async monitorDlq(): Promise<void> {
    // Minimal monitoring: log DLQ queue message counts.
    // Full alerting can be added once real admin contact routing is wired.
    const channel = this.rabbit.getChannel();
    const events: string[] = Object.keys(EVENT_DOMAIN);
    let totalDlqMessages = 0;

    for (const eventName of events) {
      const domain = EVENT_DOMAIN[eventName];
      const dlq = dlqQueueName(domain, eventName);
      try {
        const res = await channel.checkQueue(dlq);
        if (res.messageCount > 0) {
          this.logger.warn(`DLQ has ${res.messageCount} messages: ${dlq}`);
          totalDlqMessages += res.messageCount;
        }
      } catch (e) {
        this.logger.debug(`DLQ check failed for ${dlq}: ${(e as Error).message}`);
      }
    }

    if (!totalDlqMessages) return;

    const superAdmin = await this.prisma.user.findFirst({
      where: { roles: { has: 'SUPER_ADMIN' } },
      select: { id: true },
    });

    if (!superAdmin) return;

    await this.notificationService.notify(
      superAdmin.id,
      NotificationType.SYSTEM,
      'DLQ alert',
      `RabbitMQ DLQ has pending messages across event queues. Total: ${totalDlqMessages}`,
      { totalDlqMessages },
    );
  }
}
