import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as amqp from 'amqplib';
import { randomUUID } from 'node:crypto';
import {
  BASE_RETRY_DELAY_MS,
  dlqQueueName,
  domainExchangeName,
  EVENT_DOMAIN,
  MAX_RETRIES,
  mainQueueName,
  retryQueueName,
  type RabbitMqDomain,
} from './rabbitmq.constants';
import type { BusEnvelope, EventName } from './rabbitmq.types';
import { RedisService } from '../../redis/redis.service';

type PublishOptions = {
  correlationId?: string;
  attempt?: number;
};

@Injectable()
export class RabbitMqService implements OnModuleInit {
  private readonly logger = new Logger(RabbitMqService.name);

  private connection?: amqp.Connection;
  private channel?: amqp.Channel;

  constructor(private readonly redisService: RedisService) {}

  async onModuleInit(): Promise<void> {
    await this.connectAndInitTopology();
  }

  private async connectAndInitTopology(): Promise<void> {
    const host = process.env.RABBITMQ_HOST ?? 'localhost';
    const port = Number(process.env.RABBITMQ_PORT ?? '5672');
    const username = process.env.RABBITMQ_USERNAME ?? 'guest';
    const password = process.env.RABBITMQ_PASSWORD ?? 'guest';

    const vhost = process.env.RABBITMQ_VHOST ? `/${process.env.RABBITMQ_VHOST}` : '';
    const url = `amqp://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}:${port}${vhost}`;

    this.connection = await amqp.connect(url);
    this.channel = await this.connection.createChannel();

    // Exchanges per domain
    const domains: RabbitMqDomain[] = ['user', 'trade', 'payment'];
    for (const domain of domains) {
      await this.channel.assertExchange(domainExchangeName(domain), 'direct', { durable: true });
    }

    // Queues per event + retry queues with TTL + DLQs.
    const events: string[] = Object.keys(EVENT_DOMAIN);
    for (const eventName of events) {
      const domain = EVENT_DOMAIN[eventName];
      const mainQueue = mainQueueName(domain, eventName);
      const dlq = dlqQueueName(domain, eventName);

      await this.channel.assertQueue(mainQueue, { durable: true });
      await this.channel.bindQueue(mainQueue, domainExchangeName(domain), eventName);

      await this.channel.assertQueue(dlq, { durable: true });

      // Retry queues: attempt 1..MAX_RETRIES-1 (attempt MAX_RETRIES goes to DLQ)
      for (let attempt = 1; attempt < MAX_RETRIES; attempt++) {
        const retryQueue = retryQueueName(domain, eventName, attempt);
        const delayMs = BASE_RETRY_DELAY_MS * Math.pow(2, attempt - 1);

        await this.channel.assertQueue(retryQueue, {
          durable: true,
          messageTtl: delayMs,
          deadLetterExchange: domainExchangeName(domain),
          deadLetterRoutingKey: eventName,
        });
      }
    }

    this.logger.log('RabbitMQ topology initialized');
  }

  getChannel(): amqp.Channel {
    if (!this.channel) throw new Error('RabbitMqService not initialized');
    return this.channel;
  }

  async publish<T>(
    eventName: EventName | string,
    payload: T,
    options: PublishOptions = {},
  ): Promise<string> {
    const domain = EVENT_DOMAIN[eventName] ?? 'user';
    const exchange = domainExchangeName(domain);
    const routingKey = String(eventName);

    const envelope: BusEnvelope<T> = {
      eventId: randomUUID(),
      eventName: String(eventName),
      occurredAt: new Date().toISOString(),
      payload,
      correlationId: options.correlationId,
      attempt: options.attempt ?? 0,
    };

    const channel = this.getChannel();

    channel.publish(exchange, routingKey, Buffer.from(JSON.stringify(envelope)), {
      persistent: true,
      contentType: 'application/json',
      headers: {
        'x-event-id': envelope.eventId,
        'x-event-name': envelope.eventName,
        'x-attempt': envelope.attempt,
      },
    });

    return envelope.eventId;
  }

  async publishToDlq(
    domain: RabbitMqDomain,
    eventName: string,
    envelope: BusEnvelope,
  ): Promise<void> {
    const channel = this.getChannel();
    const dlq = dlqQueueName(domain, eventName);
    channel.sendToQueue(dlq, Buffer.from(JSON.stringify(envelope)), { persistent: true });
  }

  async publishToRetry(
    domain: RabbitMqDomain,
    eventName: string,
    envelope: BusEnvelope,
    attempt: number,
  ): Promise<void> {
    const channel = this.getChannel();
    const retryQueue = retryQueueName(domain, eventName, attempt);
    channel.sendToQueue(retryQueue, Buffer.from(JSON.stringify({ ...envelope, attempt })), {
      persistent: true,
      headers: {
        'x-event-id': envelope.eventId,
        'x-event-name': envelope.eventName,
        'x-attempt': attempt,
      },
    });
  }

  async isProcessed(processedKey: string): Promise<boolean> {
    const redis = this.redisService.getClient();
    const v = await redis.get(processedKey);
    return Boolean(v);
  }

  async markProcessed(processedKey: string, ttlSeconds = 7 * 24 * 60 * 60): Promise<boolean> {
    const redis = this.redisService.getClient();
    const res = await redis.set(processedKey, '1', 'NX', 'EX', ttlSeconds);
    return res === 'OK';
  }
}
