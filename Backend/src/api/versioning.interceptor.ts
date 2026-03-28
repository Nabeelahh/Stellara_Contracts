import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { Request, Response } from 'express';

export interface ApiVersionResponse {
  data: any;
  version: string;
  deprecated?: boolean;
  deprecationDate?: string;
  migrationGuide?: string;
}

@Injectable()
export class ApiVersioningInterceptor implements NestInterceptor {
  private readonly deprecatedVersions = {
    '1': {
      deprecated: true,
      deprecationDate: '2024-01-01',
      migrationGuide: 'https://docs.stellara.io/migration/v1-to-v2',
      sunsetDate: '2024-06-01',
    },
  };

  intercept(context: ExecutionContext, next: CallHandler): Observable<ApiVersionResponse> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    // Extract version from request
    const version = this.extractVersion(request);
    const versionInfo = this.deprecatedVersions[version];

    // Add version headers
    response.setHeader('API-Version', version);
    response.setHeader('API-Version-Status', versionInfo?.deprecated ? 'deprecated' : 'active');

    if (versionInfo?.deprecated) {
      response.setHeader('Deprecation', 'true');
      response.setHeader('Sunset', versionInfo.sunsetDate);
      response.setHeader('Link', `<${versionInfo.migrationGuide}>; rel="deprecation"`);
    }

    return next.handle().pipe(
      map((data) => ({
        data,
        version,
        deprecated: versionInfo?.deprecated,
        deprecationDate: versionInfo?.deprecationDate,
        migrationGuide: versionInfo?.migrationGuide,
      })),
    );
  }

  private extractVersion(request: Request): string {
    // Extract version from URL path
    const pathSegments = request.path.split('/');
    const apiIndex = pathSegments.indexOf('api');

    if (apiIndex !== -1 && pathSegments.length > apiIndex + 1) {
      return pathSegments[apiIndex + 1].replace('v', '');
    }

    // Extract from Accept header
    const acceptHeader = request.headers['accept-version'];
    if (acceptHeader) {
      return acceptHeader;
    }

    // Extract from custom header
    const versionHeader = request.headers['api-version'];
    if (versionHeader) {
      return versionHeader.replace('v', '');
    }

    // Default to latest version
    return '2';
  }
}
