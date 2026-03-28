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

export enum ContractStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  DEPRECATED = 'deprecated',
}

@Entity('contract_metadata')
export class ContractMetadata {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'contract_address', unique: true })
  contractAddress: string;

  @Column({ name: 'contract_name' })
  contractName: string;

  @Column({ name: 'contract_version' })
  contractVersion: string;

  @Column({ name: 'user_id' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({
    type: 'enum',
    enum: ContractStatus,
    default: ContractStatus.ACTIVE,
    name: 'status',
  })
  status: ContractStatus;

  @Column({ type: 'jsonb', name: 'abi_definition' })
  abiDefinition: Record<string, any>;

  @Column({ type: 'jsonb', name: 'function_metadata' })
  functionMetadata: Record<string, any>;

  @Column({ name: 'network_passphrase' })
  networkPassphrase: string;

  @Column({ name: 'deployed_at', nullable: true })
  deployedAt: Date;

  @Column({ name: 'deployed_by', nullable: true })
  deployedBy: string;

  @Column({ name: 'total_transactions', default: 0 })
  totalTransactions: number;

  @Column({ name: 'last_activity_at', nullable: true })
  lastActivityAt: Date;

  @Column({ type: 'jsonb', name: 'custom_metadata', nullable: true })
  customMetadata: Record<string, any>;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
