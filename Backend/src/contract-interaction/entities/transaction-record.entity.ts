import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

export enum TransactionStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  FAILED = 'failed',
  TIMEOUT = 'timeout',
}

export enum TransactionType {
  CONTRACT_CALL = 'contract_call',
  DEPLOY = 'deploy',
  TRANSFER = 'transfer',
  MULTISIG = 'multisig',
}

@Entity('transaction_records')
export class TransactionRecord {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'transaction_hash', unique: true })
  transactionHash: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ name: 'contract_id', nullable: true })
  contractId: string;

  @Column({
    type: 'enum',
    enum: TransactionType,
    name: 'transaction_type',
  })
  transactionType: TransactionType;

  @Column({
    type: 'enum',
    enum: TransactionStatus,
    default: TransactionStatus.PENDING,
    name: 'status',
  })
  status: TransactionStatus;

  @Column({ type: 'jsonb', name: 'function_call' })
  functionCall: Record<string, any>;

  @Column({ type: 'jsonb', name: 'result_data', nullable: true })
  resultData: Record<string, any>;

  @Column({ type: 'jsonb', name: 'error_data', nullable: true })
  errorData: Record<string, any>;

  @Column({ name: 'gas_used', type: 'bigint', nullable: true })
  gasUsed: bigint;

  @Column({ name: 'gas_price', type: 'bigint', nullable: true })
  gasPrice: bigint;

  @Column({ name: 'fee_paid', type: 'bigint', nullable: true })
  feePaid: bigint;

  @Column({ name: 'nonce', nullable: true })
  nonce: number;

  @Column({ name: 'block_number', nullable: true })
  blockNumber: number;

  @Column({ name: 'block_timestamp', nullable: true })
  blockTimestamp: Date;

  @Column({ name: 'confirmations', default: 0 })
  confirmations: number;

  @Column({ name: 'is_multisig', default: false })
  isMultisig: boolean;

  @Column({ type: 'jsonb', name: 'multisig_data', nullable: true })
  multisigData: Record<string, any>;

  @Column({ name: 'polling_attempts', default: 0 })
  pollingAttempts: number;

  @Column({ name: 'last_polled_at', nullable: true })
  lastPolledAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
