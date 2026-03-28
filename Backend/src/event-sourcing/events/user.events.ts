import { BaseDomainEvent, EventMetadata } from './event.base';

/**
 * UserRegistered Event
 * Emitted when a new user registers
 */
export class UserRegisteredEvent extends BaseDomainEvent {
  readonly payload: {
    userId: string;
    email: string;
    walletAddress: string;
    kycStatus: string;
    registeredAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      userId: string;
      email: string;
      walletAddress: string;
      kycStatus: string;
      registeredAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'UserRegistered', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * UserEmailUpdated Event
 * Emitted when user updates their email
 */
export class UserEmailUpdatedEvent extends BaseDomainEvent {
  readonly payload: {
    oldEmail: string;
    newEmail: string;
    updatedAt: Date;
  };

  constructor(
    aggregateId: string,
    payload: {
      oldEmail: string;
      newEmail: string;
      updatedAt: Date;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'UserEmailUpdated', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}

/**
 * UserKycStatusChanged Event
 * Emitted when user's KYC status changes
 */
export class UserKycStatusChangedEvent extends BaseDomainEvent {
  readonly payload: {
    oldStatus: string;
    newStatus: string;
    verifiedAt?: Date;
    reason?: string;
  };

  constructor(
    aggregateId: string,
    payload: {
      oldStatus: string;
      newStatus: string;
      verifiedAt?: Date;
      reason?: string;
    },
    metadata: EventMetadata,
    version: number,
    eventId?: string,
    occurredAt?: Date,
  ) {
    super(aggregateId, 'UserKycStatusChanged', version, metadata, eventId, occurredAt, 1);
    this.payload = payload;
  }
}
