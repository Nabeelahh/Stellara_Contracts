import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { Workflow } from './entities/workflow.entity';
import { WorkflowStep } from './entities/workflow-step.entity';
import { WorkflowExecutionService } from './services/workflow-execution.service';
import { WorkflowStateMachineService } from './services/workflow-state-machine.service';
import { IdempotencyService } from './services/idempotency.service';
import { WorkflowService } from './services/workflow.service';
import { CompensationService } from './services/compensation.service';
import { RecoveryService } from './services/recovery.service';
import { MonitoringService } from './services/monitoring.service';
import { WorkflowAdminController } from './controllers/workflow-admin.controller';

@Module({
  imports: [
    ConfigModule,
    ScheduleModule.forRoot(),
    TypeOrmModule.forFeature([Workflow, WorkflowStep]),
  ],
  controllers: [WorkflowAdminController],
  providers: [
    WorkflowExecutionService,
    WorkflowStateMachineService,
    IdempotencyService,
    WorkflowService,
    CompensationService,
    RecoveryService,
    MonitoringService,
  ],
  exports: [
    WorkflowExecutionService,
    WorkflowStateMachineService,
    IdempotencyService,
    WorkflowService,
    CompensationService,
    RecoveryService,
    MonitoringService,
  ],
})
export class WorkflowModule {}
