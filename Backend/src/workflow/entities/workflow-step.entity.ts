import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { StepState } from '../types/step-state.enum';
import { Workflow } from './workflow.entity';

@Entity('workflow_steps')
@Index(['workflowId'])
@Index(['state'])
export class WorkflowStep {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  workflowId: string;

  @Column()
  stepName: string;

  @Column()
  stepIndex: number;

  @Column({
    type: 'enum',
    enum: StepState,
    default: StepState.PENDING,
  })
  state: StepState;

  @Column('jsonb', { nullable: true })
  input?: Record<string, any>;

  @Column('jsonb', { nullable: true })
  output?: Record<string, any>;

  @Column('jsonb', { nullable: true })
  config?: Record<string, any>;

  @Column('jsonb', { nullable: true })
  resumableState?: Record<string, any>;

  @Column({ default: 0 })
  retryCount: number;

  @Column({ default: 3 })
  maxRetries: number;

  @Column({ type: 'timestamp', nullable: true })
  startedAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  completedAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  failedAt?: Date;

  @Column({ nullable: true })
  failureReason?: string;

  @Column({ type: 'timestamp', nullable: true })
  nextRetryAt?: Date;

  @Column({ default: false })
  requiresCompensation: boolean;

  @Column({ default: false })
  isCompensated: boolean;

  @Column({ type: 'timestamp', nullable: true })
  compensatedAt?: Date;

  @Column({ nullable: true })
  compensationStepName?: string;

  @Column('jsonb', { nullable: true })
  compensationConfig?: Record<string, any>;

  @Column({ default: false })
  isIdempotent: boolean;

  @Column({ nullable: true })
  idempotencyKey?: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => Workflow, (workflow) => workflow.steps, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'workflowId' })
  workflow: Workflow;
}
