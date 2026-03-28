import { Module } from '@nestjs/common';
import { RedisModule } from '../../redis/redis.module';
import { NotificationModule } from '../../notification/notification.module';
import { RabbitMqService } from './rabbitmq.service';
import { RabbitMqConsumerService } from './rabbitmq-consumer.service';
import { EventBusService } from './event-bus.service';
import { WebhooksModule } from '../../webhooks/webhooks.module';

@Module({
  imports: [RedisModule, NotificationModule, WebhooksModule],
  providers: [RabbitMqService, RabbitMqConsumerService, EventBusService],
  exports: [EventBusService],
})
export class RabbitmqModule {}
