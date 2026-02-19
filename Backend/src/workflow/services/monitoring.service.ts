import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Between } from 'typeorm';
import { Workflow } from '../entities/workflow.entity';
import { WorkflowStep } from '../entities/workflow-step.entity';
import { WorkflowState } from '../types/workflow-state.enum';
import { StepState } from '../types/step-state.enum';

@Injectable()
export class MonitoringService {
  private readonly logger = new Logger(MonitoringService.name);

  constructor(
    @InjectRepository(Workflow)
    private readonly workflowRepository: Repository<Workflow>,
    @InjectRepository(WorkflowStep)
    private readonly stepRepository: Repository<WorkflowStep>,
  ) {}

  /**
   * Get workflow statistics and metrics
   */
  async getWorkflowMetrics(timeRangeHours: number = 24): Promise<{
    totalWorkflows: number;
    workflowsByState: Record<WorkflowState, number>;
    averageDuration: number;
    successRate: number;
    failureRate: number;
    retryRate: number;
  }> {
    const since = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);
    
    const workflows = await this.workflowRepository.find({
      where: {
        createdAt: Between(since, new Date()),
      },
    });

    const totalWorkflows = workflows.length;
    
    // Count workflows by state
    const workflowsByState = {
      [WorkflowState.PENDING]: 0,
      [WorkflowState.RUNNING]: 0,
      [WorkflowState.COMPLETED]: 0,
      [WorkflowState.FAILED]: 0,
      [WorkflowState.CANCELLED]: 0,
      [WorkflowState.COMPENSATING]: 0,
      [WorkflowState.COMPENSATED]: 0,
    };

    let totalDuration = 0;
    let completedCount = 0;
    let failedCount = 0;
    let retryCount = 0;

    workflows.forEach(workflow => {
      workflowsByState[workflow.state]++;
      
      if (workflow.state === WorkflowState.COMPLETED && workflow.startedAt && workflow.completedAt) {
        totalDuration += workflow.completedAt.getTime() - workflow.startedAt.getTime();
        completedCount++;
      }
      
      if (workflow.state === WorkflowState.FAILED) {
        failedCount++;
      }
      
      retryCount += workflow.retryCount;
    });

    const averageDuration = completedCount > 0 ? totalDuration / completedCount : 0;
    const successRate = totalWorkflows > 0 ? (completedCount / totalWorkflows) * 100 : 0;
    const failureRate = totalWorkflows > 0 ? (failedCount / totalWorkflows) * 100 : 0;
    const retryRate = totalWorkflows > 0 ? (retryCount / totalWorkflows) : 0;

    return {
      totalWorkflows,
      workflowsByState,
      averageDuration,
      successRate,
      failureRate,
      retryRate,
    };
  }

  /**
   * Get step-level metrics
   */
  async getStepMetrics(timeRangeHours: number = 24): Promise<{
    totalSteps: number;
    stepsByState: Record<StepState, number>;
    averageStepDuration: number;
    stepSuccessRate: number;
    stepFailureRate: number;
    mostFailedSteps: Array<{ stepName: string; failureCount: number }>;
  }> {
    const since = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);
    
    const steps = await this.stepRepository.find({
      where: {
        createdAt: Between(since, new Date()),
      },
      relations: ['workflow'],
    });

    const totalSteps = steps.length;
    
    const stepsByState = {
      [StepState.PENDING]: 0,
      [StepState.RUNNING]: 0,
      [StepState.COMPLETED]: 0,
      [StepState.FAILED]: 0,
      [StepState.SKIPPED]: 0,
      [StepState.COMPENSATING]: 0,
      [StepState.COMPENSATED]: 0,
    };

    let totalStepDuration = 0;
    let completedSteps = 0;
    let failedSteps = 0;
    const stepFailureCounts: Record<string, number> = {};

    steps.forEach(step => {
      stepsByState[step.state]++;
      
      if (step.state === StepState.COMPLETED && step.startedAt && step.completedAt) {
        totalStepDuration += step.completedAt.getTime() - step.startedAt.getTime();
        completedSteps++;
      }
      
      if (step.state === StepState.FAILED) {
        failedSteps++;
        stepFailureCounts[step.stepName] = (stepFailureCounts[step.stepName] || 0) + 1;
      }
    });

    // Get top 5 most failed steps
    const mostFailedSteps = Object.entries(stepFailureCounts)
      .map(([stepName, failureCount]) => ({ stepName, failureCount }))
      .sort((a, b) => b.failureCount - a.failureCount)
      .slice(0, 5);

    const averageStepDuration = completedSteps > 0 ? totalStepDuration / completedSteps : 0;
    const stepSuccessRate = totalSteps > 0 ? (completedSteps / totalSteps) * 100 : 0;
    const stepFailureRate = totalSteps > 0 ? (failedSteps / totalSteps) * 100 : 0;

    return {
      totalSteps,
      stepsByState,
      averageStepDuration,
      stepSuccessRate,
      stepFailureRate,
      mostFailedSteps,
    };
  }

  /**
   * Get workflow timeline for debugging
   */
  async getWorkflowTimeline(workflowId: string): Promise<Array<{
    timestamp: Date;
    eventType: string;
    description: string;
    metadata?: any;
  }>> {
    const workflow = await this.workflowRepository.findOne({
      where: { id: workflowId },
      relations: ['steps'],
    });

    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    const timeline: Array<{
      timestamp: Date;
      eventType: string;
      description: string;
      metadata?: any;
    }> = [];

    // Workflow creation
    timeline.push({
      timestamp: workflow.createdAt,
      eventType: 'WORKFLOW_CREATED',
      description: `Workflow ${workflow.type} created`,
      metadata: {
        idempotencyKey: workflow.idempotencyKey,
        userId: workflow.userId,
        walletAddress: workflow.walletAddress,
      },
    });

    // Workflow started
    if (workflow.startedAt) {
      timeline.push({
        timestamp: workflow.startedAt,
        eventType: 'WORKFLOW_STARTED',
        description: 'Workflow execution started',
      });
    }

    // Step events
    for (const step of workflow.steps.sort((a, b) => a.stepIndex - b.stepIndex)) {
      if (step.startedAt) {
        timeline.push({
          timestamp: step.startedAt,
          eventType: 'STEP_STARTED',
          description: `Step '${step.stepName}' started`,
          metadata: {
            stepIndex: step.stepIndex,
            retryCount: step.retryCount,
          },
        });
      }

      if (step.completedAt) {
        timeline.push({
          timestamp: step.completedAt,
          eventType: 'STEP_COMPLETED',
          description: `Step '${step.stepName}' completed`,
          metadata: {
            duration: step.completedAt.getTime() - (step.startedAt?.getTime() || step.completedAt.getTime()),
            outputKeys: step.output ? Object.keys(step.output) : [],
          },
        });
      }

      if (step.failedAt) {
        timeline.push({
          timestamp: step.failedAt,
          eventType: 'STEP_FAILED',
          description: `Step '${step.stepName}' failed`,
          metadata: {
            failureReason: step.failureReason,
            retryCount: step.retryCount,
          },
        });
      }

      if (step.compensatedAt) {
        timeline.push({
          timestamp: step.compensatedAt,
          eventType: 'STEP_COMPENSATED',
          description: `Step '${step.stepName}' compensated`,
        });
      }
    }

    // Workflow completion/failure
    if (workflow.completedAt) {
      timeline.push({
        timestamp: workflow.completedAt,
        eventType: 'WORKFLOW_COMPLETED',
        description: 'Workflow completed successfully',
        metadata: {
          totalDuration: workflow.completedAt.getTime() - workflow.startedAt!.getTime(),
          totalSteps: workflow.totalSteps,
          retryCount: workflow.retryCount,
        },
      });
    }

    if (workflow.failedAt) {
      timeline.push({
        timestamp: workflow.failedAt,
        eventType: 'WORKFLOW_FAILED',
        description: 'Workflow failed',
        metadata: {
          failureReason: workflow.failureReason,
          currentStep: workflow.currentStepIndex,
          retryCount: workflow.retryCount,
        },
      });
    }

    if (workflow.isCompensated) {
      timeline.push({
        timestamp: workflow.completedAt || workflow.updatedAt,
        eventType: 'WORKFLOW_COMPENSATED',
        description: 'Workflow compensation completed',
      });
    }

    // Sort timeline by timestamp
    return timeline.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }

  /**
   * Get system health metrics
   */
  async getSystemHealth(): Promise<{
    databaseConnection: boolean;
    workflowEngineStatus: 'healthy' | 'degraded' | 'unhealthy';
    pendingWorkflows: number;
    runningWorkflows: number;
    recentFailures: number;
    averageResponseTime: number;
  }> {
    let databaseConnection = true;
    
    try {
      await this.workflowRepository.query('SELECT 1');
    } catch (error) {
      databaseConnection = false;
      this.logger.error('Database connection check failed:', error);
    }

    const pendingWorkflows = await this.workflowRepository.count({
      where: { state: WorkflowState.PENDING },
    });

    const runningWorkflows = await this.workflowRepository.count({
      where: { state: WorkflowState.RUNNING },
    });

    const recentFailures = await this.workflowRepository.count({
      where: { 
        state: WorkflowState.FAILED,
        failedAt: Between(
          new Date(Date.now() - 60 * 60 * 1000), // Last hour
          new Date()
        )
      },
    });

    // Calculate average response time from recent completed workflows
    const recentCompleted = await this.workflowRepository.find({
      where: {
        state: WorkflowState.COMPLETED,
        completedAt: Between(
          new Date(Date.now() - 60 * 60 * 1000),
          new Date()
        )
      },
    });

    let averageResponseTime = 0;
    if (recentCompleted.length > 0) {
      const totalDuration = recentCompleted.reduce((sum, workflow) => {
        if (workflow.startedAt && workflow.completedAt) {
          return sum + (workflow.completedAt.getTime() - workflow.startedAt.getTime());
        }
        return sum;
      }, 0);
      averageResponseTime = totalDuration / recentCompleted.length;
    }

    // Determine system health
    let workflowEngineStatus: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    
    if (!databaseConnection) {
      workflowEngineStatus = 'unhealthy';
    } else if (recentFailures > 10 || runningWorkflows > 1000) {
      workflowEngineStatus = 'degraded';
    }

    return {
      databaseConnection,
      workflowEngineStatus,
      pendingWorkflows,
      runningWorkflows,
      recentFailures,
      averageResponseTime,
    };
  }

  /**
   * Get workflow type distribution
   */
  async getWorkflowTypeDistribution(timeRangeHours: number = 24): Promise<
    Array<{ type: string; count: number; successRate: number }>
  > {
    const since = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);
    
    const workflows = await this.workflowRepository.find({
      where: {
        createdAt: Between(since, new Date()),
      },
    });

    const typeStats: Record<string, { total: number; completed: number }> = {};

    workflows.forEach(workflow => {
      if (!typeStats[workflow.type]) {
        typeStats[workflow.type] = { total: 0, completed: 0 };
      }
      
      typeStats[workflow.type].total++;
      if (workflow.state === WorkflowState.COMPLETED) {
        typeStats[workflow.type].completed++;
      }
    });

    return Object.entries(typeStats).map(([type, stats]) => ({
      type,
      count: stats.total,
      successRate: stats.total > 0 ? (stats.completed / stats.total) * 100 : 0,
    }));
  }
}