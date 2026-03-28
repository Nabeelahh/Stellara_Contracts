export type RabbitMqDomain = 'user' | 'trade' | 'payment';

export const EVENT_DOMAIN: Record<string, RabbitMqDomain> = {
  UserCreated: 'user',
  TradeExecuted: 'trade',
  PaymentProcessed: 'payment',
};

export function domainExchangeName(domain: RabbitMqDomain): string {
  return `stellara.${domain}`;
}

export function mainQueueName(domain: RabbitMqDomain, eventName: string): string {
  return `stellara.${domain}.queue.${eventName}`;
}

export function retryQueueName(domain: RabbitMqDomain, eventName: string, attempt: number): string {
  return `stellara.${domain}.queue.${eventName}.retry.${attempt}`;
}

export function dlqQueueName(domain: RabbitMqDomain, eventName: string): string {
  return `stellara.${domain}.queue.${eventName}.dlq`;
}

export const MAX_RETRIES = Number(process.env.RABBITMQ_MAX_RETRIES ?? 5);
export const BASE_RETRY_DELAY_MS = Number(process.env.RABBITMQ_BASE_RETRY_DELAY_MS ?? 5000);
