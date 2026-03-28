export type EventName = 'UserCreated' | 'TradeExecuted' | 'PaymentProcessed';

export type BusEnvelope<T = unknown> = {
  eventId: string;
  eventName: EventName | string;
  occurredAt: string; // ISO string
  payload: T;
  correlationId?: string;
  attempt: number;
};
