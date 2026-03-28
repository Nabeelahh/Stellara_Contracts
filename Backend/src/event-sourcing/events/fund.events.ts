import { BaseDomainEvent, EventMetadata } from './event.base';

/**
 * FundDeposited Event
 * Emitted when funds are deposited into user account
 */
export class FundDepositedEvent extends BaseDomainEvent {
  readonly payload: {
    userId: string;
    asset: string;
    amount: string;
    txHash: string;
    sourceAddress: string;
    depositedAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      userId: string;
      asset: string;
      amount: string;
      txHash: string;
      sourceAddress: string;
      depositedAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'FundDeposited', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * FundWithdrawn Event
 * Emitted when funds are withdrawn from user account
 */
export class FundWithdrawnEvent extends BaseDomainEvent {
  readonly payload: {
    userId: string;
    asset: string;
    amount: string;
    txHash: string;
    destinationAddress: string;
    fee: string;
    withdrawnAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      userId: string;
      asset: string;
      amount: string;
      txHash: string;
      destinationAddress: string;
      fee: string;
      withdrawnAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'FundWithdrawn', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * FundReserved Event
 * Emitted when funds are reserved for an order
 */
export class FundReservedEvent extends BaseDomainEvent {
  readonly payload: {
    userId: string;
    orderId: string;
    asset: string;
    amount: string;
    reservedAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      userId: string;
      orderId: string;
      asset: string;
      amount: string;
      reservedAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'FundReserved', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * FundReleased Event
 * Emitted when reserved funds are released
 */
export class FundReleasedEvent extends BaseDomainEvent {
  readonly payload: {
    userId: string;
    orderId: string;
    asset: string;
    amount: string;
    reason: string;
    releasedAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      userId: string;
      orderId: string;
      asset: string;
      amount: string;
      reason: string;
      releasedAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'FundReleased', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}
