import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  OneToMany,
} from 'typeorm';
import { WorkflowState } from '../types/workflow-state.enum';
import { WorkflowType } from '../types/workflow-type.enum';
import { WorkflowStep } from './workflow-step.entity';

@Entity('workflows')
@Index(['idempotencyKey'])
@Index(['state'])
@Index(['type'])
@Index(['userId'])
export class Workflow {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  idempotencyKey: string;

  @Column({ default: 1 })
  version: number;

  @Column('jsonb', { nullable: true })
  definition?: Record<string, any>;

  @Column('jsonb', { nullable: true })
  recoveryMetadata?: Record<string, any>;

  @Column({
    type: 'enum',
    enum: WorkflowType,
  })
  type: WorkflowType;

  @Column({
    type: 'enum',
    enum: WorkflowState,
    default: WorkflowState.PENDING,
  })
  state: WorkflowState;

  @Column({ nullable: true })
  userId?: string;

  @Column({ nullable: true })
  walletAddress?: string;

  @Column('jsonb')
  input: Record<string, any>;

  @Column('jsonb', { nullable: true })
  output?: Record<string, any>;

  @Column('jsonb', { nullable: true })
  context?: Record<string, any>;

  @Column({ default: 0 })
  currentStepIndex: number;

  @Column({ default: 0 })
  totalSteps: number;

  @Column({ type: 'timestamp', nullable: true })
  startedAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  completedAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  failedAt?: Date;

  @Column({ nullable: true })
  failureReason?: string;

  @Column({ default: 0 })
  retryCount: number;

  @Column({ default: 3 })
  maxRetries: number;

  @Column({ type: 'timestamp', nullable: true })
  nextRetryAt?: Date;

  @Column({ default: false })
  requiresCompensation: boolean;

  @Column({ default: false })
  isCompensated: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => WorkflowStep, (step) => step.workflow, { cascade: true })
  steps: WorkflowStep[];
}
