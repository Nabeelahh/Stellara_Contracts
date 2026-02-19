import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, LessThan, Repository } from 'typeorm';
import { Workflow } from '../entities/workflow.entity';
import { WorkflowStep } from '../entities/workflow-step.entity';
import { WorkflowState } from '../types/workflow-state.enum';
import { StepState } from '../types/step-state.enum';
import { WorkflowExecutionService } from './workflow-execution.service';
import { CompensationService } from './compensation.service';
import { RecoveryService } from './recovery.service';
import { MonitoringService } from './monitoring.service';
import { contractDeploymentWorkflow } from '../examples/contract-deployment.workflow';
import { tradeExecutionWorkflow } from '../examples/trade-execution.workflow';
import { aiJobChainWorkflow } from '../examples/ai-job-chain.workflow';

@Injectable()
export class WorkflowService implements OnModuleInit {
  private readonly logger = new Logger(WorkflowService.name);

  constructor(
    @InjectRepository(Workflow)
    private readonly workflowRepository: Repository<Workflow>,
    @InjectRepository(WorkflowStep)
    private readonly stepRepository: Repository<WorkflowStep>,
    private readonly workflowExecutionService: WorkflowExecutionService,
    private readonly compensationService: CompensationService,
    private readonly recoveryService: RecoveryService,
    private readonly monitoringService: MonitoringService,
  ) {}

  async onModuleInit() {
    // Register built-in workflow definitions
    this.workflowExecutionService.registerWorkflowDefinition(contractDeploymentWorkflow);
    this.workflowExecutionService.registerWorkflowDefinition(tradeExecutionWorkflow);
    this.workflowExecutionService.registerWorkflowDefinition(aiJobChainWorkflow);
    
    this.logger.log('WorkflowService initialized with built-in workflow definitions');
  }

  /**
   * Start a new workflow
   */
  async startWorkflow(
    type: string,
    input: Record<string, any>,
    userId?: string,
    walletAddress?: string,
    context?: Record<string, any>,
  ): Promise<Workflow> {
    this.logger.log(`Starting workflow of type: ${type} for user: ${userId}`);
    
    return await this.workflowExecutionService.startWorkflow(
      type,
      input,
      userId,
      walletAddress,
      context,
    );
  }

  /**
   * Get workflow by ID
   */
  async getWorkflow(id: string): Promise<Workflow | null> {
    return await this.workflowRepository.findOne({
      where: { id },
      relations: ['steps'],
    });
  }

  /**
   * Get workflows by user
   */
  async getUserWorkflows(
    userId: string,
    page: number = 1,
    limit: number = 20,
  ): Promise<{ workflows: Workflow[]; total: number }> {
    const skip = (page - 1) * limit;
    
    const [workflows, total] = await this.workflowRepository.findAndCount({
      where: { userId },
      relations: ['steps'],
      order: { createdAt: 'DESC' },
      skip,
      take: limit,
    });

    return { workflows, total };
  }

  /**
   * Get workflows by wallet address
   */
  async getWalletWorkflows(
    walletAddress: string,
    page: number = 1,
    limit: number = 20,
  ): Promise<{ workflows: Workflow[]; total: number }> {
    const skip = (page - 1) * limit;
    
    const [workflows, total] = await this.workflowRepository.findAndCount({
      where: { walletAddress },
      relations: ['steps'],
      order: { createdAt: 'DESC' },
      skip,
      take: limit,
    });

    return { workflows, total };
  }

  /**
   * Get workflows by state
   */
  async getWorkflowsByState(
    state: WorkflowState,
    page: number = 1,
    limit: number = 20,
  ): Promise<{ workflows: Workflow[]; total: number }> {
    const skip = (page - 1) * limit;
    
    const [workflows, total] = await this.workflowRepository.findAndCount({
      where: { state },
      relations: ['steps'],
      order: { createdAt: 'DESC' },
      skip,
      take: limit,
    });

    return { workflows, total };
  }

  /**
   * Retry a failed workflow
   */
  async retryWorkflow(workflowId: string): Promise<void> {
    await this.workflowExecutionService.retryWorkflow(workflowId);
  }

  /**
   * Compensate a failed workflow
   */
  async compensateWorkflow(workflowId: string): Promise<void> {
    await this.compensationService.compensateWorkflow(workflowId);
  }

  /**
   * Get compensatable workflows
   */
  async getCompensatableWorkflows(): Promise<Workflow[]> {
    return await this.compensationService.getCompensatableWorkflows();
  }

  /**
   * Trigger manual recovery
   */
  async triggerRecovery(): Promise<any> {
    return await this.recoveryService.triggerManualRecovery();
  }

  /**
   * Get workflow metrics
   */
  async getWorkflowMetrics(timeRangeHours: number = 24): Promise<any> {
    return await this.monitoringService.getWorkflowMetrics(timeRangeHours);
  }

  /**
   * Get step metrics
   */
  async getStepMetrics(timeRangeHours: number = 24): Promise<any> {
    return await this.monitoringService.getStepMetrics(timeRangeHours);
  }

  /**
   * Get workflow timeline for debugging
   */
  async getWorkflowTimeline(workflowId: string): Promise<any> {
    return await this.monitoringService.getWorkflowTimeline(workflowId);
  }

  /**
   * Get system health status
   */
  async getSystemHealth(): Promise<any> {
    return await this.monitoringService.getSystemHealth();
  }

  /**
   * Get failed workflows that can be retried
   */
  async getRetryableWorkflows(): Promise<Workflow[]> {
    return await this.workflowRepository.find({
      where: { 
        state: WorkflowState.FAILED,
        retryCount: 0, // Only show workflows that haven't been retried
      },
      relations: ['steps'],
      order: { failedAt: 'DESC' },
    });
  }

  /**
   * Get workflows that need compensation
   */
  async getCompensableWorkflows(): Promise<Workflow[]> {
    return await this.workflowRepository.find({
      where: { 
        requiresCompensation: true,
        isCompensated: false,
        state: In([WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.CANCELLED]),
      },
      relations: ['steps'],
      order: { createdAt: 'DESC' },
    });
  }

  /**
   * Cancel a workflow
   */
  async cancelWorkflow(id: string): Promise<void> {
    await this.workflowExecutionService.cancelWorkflow(id);
  }

  /**
   * Clean up old completed workflows
   */
  async cleanupOldWorkflows(daysOld: number = 30): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    const result = await this.workflowRepository.delete({
      state: In([WorkflowState.COMPLETED, WorkflowState.COMPENSATED]),
      completedAt: LessThan(cutoffDate),
    });

    this.logger.log(`Cleaned up ${result.affected} old workflows`);
    return result.affected || 0;
  }

  /**
   * Get workflows that need retry (failed and within retry window)
   */
  async getWorkflowsNeedingRetry(): Promise<Workflow[]> {
    const now = new Date();
    
    return await this.workflowRepository.find({
      where: {
        state: WorkflowState.FAILED,
        retryCount: 0, // Only workflows that haven't been retried yet
        nextRetryAt: LessThan(now),
      },
      relations: ['steps'],
      order: { nextRetryAt: 'ASC' },
    });
  }

  /**
   * Process workflows that need retry
   */
  async processRetryQueue(): Promise<number> {
    const workflowsToRetry = await this.getWorkflowsNeedingRetry();
    
    for (const workflow of workflowsToRetry) {
      try {
        this.logger.log(`Retrying workflow: ${workflow.id}`);
        await this.retryWorkflow(workflow.id);
      } catch (error) {
        this.logger.error(`Failed to retry workflow ${workflow.id}:`, error);
      }
    }

    return workflowsToRetry.length;
  }
}
