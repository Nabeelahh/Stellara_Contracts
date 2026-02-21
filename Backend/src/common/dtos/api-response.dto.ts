import { SetMetadata, applyDecorators } from '@nestjs/common';
import {
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiUnauthorizedResponse,
  ApiForbiddenResponse,
  ApiInternalServerErrorResponse,
} from '@nestjs/swagger';
import { ErrorResponseDto } from '../dtos/api-response.dto';

export const DOCUMENTED_KEY = 'isDocumented';


export function ApiDocumented(options: {
  summary: string;
  description?: string;
  requiresAuth?: boolean;
  deprecated?: boolean;
}) {
  const decorators = [
    SetMetadata(DOCUMENTED_KEY, true),
    ApiOperation({
      summary: options.summary,
      description: options.description,
      deprecated: options.deprecated,
    }),
    ApiUnauthorizedResponse({
      description: 'Missing or invalid bearer token',
      type: ErrorResponseDto,
    }),
    ApiForbiddenResponse({
      description: 'Insufficient permissions',
      type: ErrorResponseDto,
    }),
    ApiInternalServerErrorResponse({
      description: 'Unexpected server error',
      type: ErrorResponseDto,
    }),
  ];

  if (options.requiresAuth !== false) {
    decorators.push(ApiBearerAuth('JWT'));
  }

  return applyDecorators(...decorators);
}

export const ApiPrivate = () => SetMetadata('apiPrivate', true);