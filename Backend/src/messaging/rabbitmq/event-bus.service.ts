import { Injectable } from '@nestjs/common';
import { RabbitMqService } from './rabbitmq.service';
import type { EventName } from './rabbitmq.types';
import { WebhooksService } from '../../webhooks/webhooks.service';

@Injectable()
export class EventBusService {
  constructor(
    private readonly rabbit: RabbitMqService,
    private readonly webhooksService: WebhooksService,
  ) {}

  async publish<T>(eventName: EventName, payload: T, correlationId?: string): Promise<string> {
    const eventId = await this.rabbit.publish(eventName, payload, { correlationId });

    await this.webhooksService.publishEvent({
      eventType: eventName,
      payload: payload as Record<string, unknown>,
      metadata: correlationId ? { correlationId, eventId } : { eventId },
      source: 'event-bus',
    });

    return eventId;
  }
}
