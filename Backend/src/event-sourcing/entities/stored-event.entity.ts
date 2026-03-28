import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

/**
 * Entity representing a stored event in the event store
 * Maps to the events table in PostgreSQL
 */
@Entity('events')
@Index(['aggregateId', 'version'], { unique: true })
@Index(['eventType'])
@Index(['occurredAt'])
@Index(['correlationId'])
export class StoredEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  eventId: string;

  @Column({ type: 'varchar', length: 255 })
  aggregateId: string;

  @Column({ type: 'varchar', length: 100 })
  aggregateType: string;

  @Column({ type: 'varchar', length: 100 })
  eventType: string;

  @Column({ type: 'int' })
  version: number;

  @Column({ type: 'jsonb' })
  payload: Record<string, unknown>;

  @Column({ type: 'jsonb', default: {} })
  metadata: Record<string, unknown>;

  @Column({ type: 'int', default: 1 })
  schemaVersion: number;

  @CreateDateColumn({ type: 'timestamptz' })
  occurredAt: Date;

  @Column({ type: 'uuid', nullable: true })
  correlationId: string;

  @Column({ type: 'uuid', nullable: true })
  causationId: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  userId: string;

  @Column({ type: 'varchar', length: 100 })
  source: string;
}
