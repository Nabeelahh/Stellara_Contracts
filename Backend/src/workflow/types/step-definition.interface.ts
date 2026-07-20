export interface StepDefinition {
  name: string;
  execute: (input: any, context: WorkflowContext) => Promise<any>;
  compensate?: (
    input: any,
    output: any,
    context: WorkflowContext,
  ) => Promise<any>;
  isIdempotent: boolean;
  maxRetries?: number;
  timeout?: number;
  config?: Record<string, any>;
}

export interface WorkflowContext {
  workflowId: string;
  idempotencyKey: string;
  userId?: string;
  walletAddress?: string;
  type: string;
  retryCount: number;
  stepIndex: number;
  metadata?: Record<string, any>;
  resumableState?: Record<string, any>;
  updateState?: (state: Record<string, any>) => Promise<void>;
}
