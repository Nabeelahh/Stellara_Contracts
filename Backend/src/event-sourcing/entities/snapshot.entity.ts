import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Snapshot Entity
 * 
 * Stores periodic snapshots of aggregate state to optimize
 * event replay performance. Instead of replaying all events
 * from the beginning, we can start from the latest snapshot.
 */
@Entity('snapshots')
@Index(['aggregateId', 'aggregateType'])
@Index(['version'])
export class Snapshot {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  aggregateId: string;

  @Column({ type: 'varchar', length: 100 })
  aggregateType: string;

  @Column({ type: 'int' })
  version: number;

  @Column({ type: 'jsonb' })
  state: Record<string, unknown>;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;
}
