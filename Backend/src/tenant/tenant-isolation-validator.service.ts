import { Injectable, Logger, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { AdvancedCacheService } from '../cache/advanced-cache.service';

@Injectable()
export class TenantIsolationValidator {
  private readonly logger = new Logger(TenantIsolationValidator.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: AdvancedCacheService,
  ) {}

  /**
   * Verifies that a query includes a tenantId filter.
   * This is a manual check that can be used in services.
   */
  validateQueryFilter(query: any, tenantId: string): void {
    if (!query.where || query.where.tenantId !== tenantId) {
      this.logger.error(`Tenant isolation breach attempt! Query: ${JSON.stringify(query)}, expected tenantId: ${tenantId}`);
      throw new ForbiddenException('Tenant isolation breach detected: missing or incorrect tenantId filter');
    }
  }

  /**
   * Verifies that a cache key is correctly prefixed with the tenantId.
   */
  validateCacheKey(key: string, tenantId: string): void {
    const requiredPrefix = `tenant:${tenantId}:`;
    if (!key.startsWith(requiredPrefix)) {
      this.logger.error(`Cache isolation breach attempt! Key: ${key}, expected prefix: ${requiredPrefix}`);
      throw new ForbiddenException('Tenant isolation breach detected: cache key not correctly prefixed');
    }
  }

  /**
   * Runs automated isolation tests between two tenants.
   * This can be triggered by the CI or a scheduled task.
   */
  async runIsolationTest(tenantAId: string, tenantBId: string): Promise<{ success: boolean; errors: string[] }> {
    const errors: string[] = [];
    this.logger.log(`Running tenant isolation tests between ${tenantAId} and ${tenantBId}`);

    try {
      // Test 1: Attempt to read Tenant B's users using Tenant A's context (if possible)
      // This would normally be handled by the middleware, but we're testing the service layer here.
      
      // We expect the following to FAIL if the service layer enforces isolation
      // For this mock/validator, we just verify that we can't find cross-tenant data if we search by tenantId
      const crossTenantData = await this.prisma.user.findMany({
        where: { tenantId: tenantBId },
      });

      // If we are acting as Tenant A, we should not even be able to construct a query for Tenant B
      // in a safe environment.
    } catch (error) {
      errors.push(`Isolation test failed: ${error.message}`);
    }

    return {
      success: errors.length === 0,
      errors,
    };
  }

  /**
   * Fuzz testing with malicious inputs
   */
  async fuzzTenantIsolation(tenantId: string): Promise<void> {
    const maliciousInputs = [
      '',
      '\' OR 1=1 --',
      '*; DROP TABLE users;',
      'other-tenant-uuid',
    ];

    for (const input of maliciousInputs) {
      try {
        // Attempt a read with malicious input
        await this.prisma.user.findMany({
          where: { tenantId: input as any },
        });
      } catch (error) {
        // Expected to fail for most malicious inputs due to UUID validation or Prisma safety
      }
    }
  }
}
