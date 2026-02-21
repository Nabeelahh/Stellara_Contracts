import { applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiBearerAuth,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiInternalServerErrorResponse,
  ApiTooManyRequestsResponse,
} from '@nestjs/swagger';
import { ErrorResponseDto } from '../dtos/api-response.dto';

/**
 * @ApiDocumented  — composite decorator for every controller method.
 *
 * Automatically injects:
 *   • @ApiOperation  (summary + description)
 *   • @ApiBearerAuth('JWT')           (unless requiresAuth = false)
 *   • 401 / 403 / 429 / 500 responses (typed with ErrorResponseDto)
 *
 * Usage:
 *   @ApiDocumented({ summary: 'Execute a trade' })
 *   @ApiCreatedResponse({ type: TradeDto })
 *   @ApiBadRequestResponse({ type: ErrorResponseDto })
 *   async executeTrade(@Body() dto: ExecuteTradeDto) { … }
 */
export function ApiDocumented(options: {
  summary: string;
  description?: string;
  requiresAuth?: boolean;   // default true
  deprecated?: boolean;
}) {
  const decorators = [
    ApiOperation({
      summary:     options.summary,
      description: options.description,
      deprecated:  options.deprecated ?? false,
    }),
    ApiUnauthorizedResponse({
      description: 'Missing or invalid bearer token',
      type: ErrorResponseDto,
    }),
    ApiForbiddenResponse({
      description: 'Authenticated but insufficient permissions',
      type: ErrorResponseDto,
    }),
    ApiTooManyRequestsResponse({
      description: 'Rate limit exceeded',
      type: ErrorResponseDto,
    }),
    ApiInternalServerErrorResponse({
      description: 'Unexpected server error',
      type: ErrorResponseDto,
    }),
  ];

  // Apply JWT security requirement unless the endpoint is public
  if (options.requiresAuth !== false) {
    decorators.push(ApiBearerAuth('JWT'));
  }

  return applyDecorators(...decorators);
}

/**
 * @ApiPublic  — convenience alias for unauthenticated endpoints
 * (same as @ApiDocumented({ …, requiresAuth: false }))
 */
export function ApiPublic(options: {
  summary: string;
  description?: string;
}) {
  return ApiDocumented({ ...options, requiresAuth: false });
}