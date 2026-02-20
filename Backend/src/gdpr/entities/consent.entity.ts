import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';
import { User } from '../../auth/entities/user.entity';

export enum ConsentType {
  DATA_PROCESSING = 'data_processing',
  MARKETING = 'marketing',
  ANALYTICS = 'analytics',
  THIRD_PARTY_SHARING = 'third_party_sharing',
}

export enum ConsentStatus {
  GRANTED = 'granted',
  WITHDRAWN = 'withdrawn',
  EXPIRED = 'expired',
}

@Entity('consents')
@Index(['userId', 'consentType'], { unique: true })
export class Consent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, (user) => user.id)
  user: User;

  @Column({
    type: 'enum',
    enum: ConsentType,
  })
  consentType: ConsentType;

  @Column({
    type: 'enum',
    enum: ConsentStatus,
    default: ConsentStatus.GRANTED,
  })
  status: ConsentStatus;

  @Column({ type: 'varchar', length: 50 })
  version: string;

  @Column({ type: 'text', nullable: true })
  consentText?: string;

  @CreateDateColumn({ type: 'timestamp' })
  grantedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  withdrawnAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  expiresAt?: Date;

  @UpdateDateColumn({ type: 'timestamp' })
  updatedAt: Date;
}