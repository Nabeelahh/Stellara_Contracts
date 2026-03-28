import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { parse, validate, DocumentNode, GraphQLSchema, FieldNode, SelectionSetNode } from 'graphql';

const MAX_COMPLEXITY = 100;
const SCALAR_COST = 1;
const LIST_MULTIPLIER = 10;

// List-type field names that should have higher cost
const LIST_FIELDS = new Set(['users', 'calls', 'stakeLedgers', 'items']);

function calculateComplexity(selectionSet: SelectionSetNode | undefined, depth = 0): number {
  if (!selectionSet) return 0;

  let total = 0;
  for (const selection of selectionSet.selections) {
    if (selection.kind !== 'Field') continue;

    const field = selection as FieldNode;
    const fieldName = field.name.value;
    const isList = LIST_FIELDS.has(fieldName);
    const childComplexity = calculateComplexity(field.selectionSet, depth + 1);

    const fieldCost = isList
      ? LIST_MULTIPLIER + childComplexity * LIST_MULTIPLIER
      : SCALAR_COST + childComplexity;

    total += fieldCost;
  }

  return total;
}

@Injectable()
export class GraphqlComplexityGuard implements CanActivate {
  private readonly logger = new Logger(GraphqlComplexityGuard.name);

  canActivate(context: ExecutionContext): boolean {
    const gqlCtx = GqlExecutionContext.create(context);
    const info = gqlCtx.getInfo();

    if (!info || !info.operation) {
      return true; // Not a GraphQL context, allow
    }

    const complexity = calculateComplexity(info.operation.selectionSet);

    this.logger.debug(`Query complexity calculated: ${complexity} / max ${MAX_COMPLEXITY}`);

    if (complexity > MAX_COMPLEXITY) {
      this.logger.warn(`Query rejected: complexity ${complexity} exceeds max ${MAX_COMPLEXITY}`);
      throw new HttpException(
        `Query complexity (${complexity}) exceeds the maximum allowed complexity of ${MAX_COMPLEXITY}.`,
        HttpStatus.BAD_REQUEST,
      );
    }

    return true;
  }
}
