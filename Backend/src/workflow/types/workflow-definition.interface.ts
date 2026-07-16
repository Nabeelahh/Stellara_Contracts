import { StepDefinition } from './step-definition.interface';
import { WorkflowType } from './workflow-type.enum';

export interface WorkflowDefinition {
  type: WorkflowType;
  version?: number;
  name: string;
  description: string;
  steps: StepDefinition[];
  maxRetries?: number;
  timeout?: number;
  requiresCompensation?: boolean;
  metadata?: Record<string, any>;
}
