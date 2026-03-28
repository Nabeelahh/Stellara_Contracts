import { BaseDomainEvent, EventMetadata } from './event.base';

/**
 * TradeExecuted Event
 * Emitted when a trade is executed
 */
export class TradeExecutedEvent extends BaseDomainEvent {
  readonly payload: {
    tradeId: string;
    buyOrderId: string;
    sellOrderId: string;
    buyerId: string;
    sellerId: string;
    tradingPair: string;
    price: string;
    quantity: string;
    totalAmount: string;
    buyFee: string;
    sellFee: string;
    executedAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      tradeId: string;
      buyOrderId: string;
      sellOrderId: string;
      buyerId: string;
      sellerId: string;
      tradingPair: string;
      price: string;
      quantity: string;
      totalAmount: string;
      buyFee: string;
      sellFee: string;
      executedAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'TradeExecuted', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * OrderPlaced Event
 * Emitted when a new order is placed
 */
export class OrderPlacedEvent extends BaseDomainEvent {
  readonly payload: {
    orderId: string;
    userId: string;
    tradingPair: string;
    side: 'BUY' | 'SELL';
    orderType: 'LIMIT' | 'MARKET' | 'STOP_LOSS' | 'STOP_LIMIT';
    price?: string;
    quantity: string;
    timeInForce: 'GTC' | 'IOC' | 'FOK' | 'GTD';
    expiresAt?: Date;
    placedAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      orderId: string;
      userId: string;
      tradingPair: string;
      side: 'BUY' | 'SELL';
      orderType: 'LIMIT' | 'MARKET' | 'STOP_LOSS' | 'STOP_LIMIT';
      price?: string;
      quantity: string;
      timeInForce: 'GTC' | 'IOC' | 'FOK' | 'GTD';
      expiresAt?: Date;
      placedAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'OrderPlaced', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * OrderCancelled Event
 * Emitted when an order is cancelled
 */
export class OrderCancelledEvent extends BaseDomainEvent {
  readonly payload: {
    orderId: string;
    userId: string;
    reason: string;
    cancelledAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      orderId: string;
      userId: string;
      reason: string;
      cancelledAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'OrderCancelled', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * OrderFilled Event
 * Emitted when an order is partially or fully filled
 */
export class OrderFilledEvent extends BaseDomainEvent {
  readonly payload: {
    orderId: string;
    userId: string;
    filledQuantity: string;
    remainingQuantity: string;
    filledPrice: string;
    isComplete: boolean;
    filledAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      orderId: string;
      userId: string;
      filledQuantity: string;
      remainingQuantity: string;
      filledPrice: string;
      isComplete: boolean;
      filledAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'OrderFilled', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}
