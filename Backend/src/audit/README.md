# Audit Logging Module

Comprehensive audit logging system for compliance and troubleshooting, capturing all user actions, system events, and data changes.

## Features

- **Automatic Action Logging**: All HTTP requests are automatically logged via interceptor
- **Request/Response Capture**: Configurable capture of request bodies and responses
- **Data Change Tracking**: Track previous and new state for entity changes
- **Tamper-Proof Audit Trail**: SHA-256 checksums for integrity verification
- **User Context Capture**: IP address, user agent, user ID, tenant ID
- **Retention Policies**: Configurable data retention with archival support
- **Query API**: Full-featured API for audit log queries and statistics

## Usage

### Automatic Logging

All HTTP requests are automatically logged by the global `AuditInterceptor`. No code changes required.

### Decorators

```typescript
import { Audit, SkipAudit, AuditCreate, AuditUpdate, AuditDelete } from '../audit';

@Controller('users')
export class UserController {
  // Custom audit metadata
  @Post()
  @Audit({ entityType: 'User', captureRequestBody: true, captureResponseBody: true })
  async create(@Body() dto: CreateUserDto) {
    return this.userService.create(dto);
  }

  // Skip audit for health checks
  @Get('health')
  @SkipAudit()
  healthCheck() {
    return { status: 'ok' };
  }

  // Convenience decorators
  @Post()
  @AuditCreate('User')
  async createUser() { ... }

  @Put(':id')
  @AuditUpdate('User')
  async updateUser() { ... }

  @Delete(':id')
  @AuditDelete('User')
  async deleteUser() { ... }
}
```

### Programmatic Logging

```typescript
import { AuditService } from '../audit';

@Injectable()
export class SomeService {
  constructor(private readonly auditService: AuditService) {}

  async doSomething() {
    // Log a data change
    await this.auditService.logDataChange(AuditAction.UPDATE, {
      entityType: 'Setting',
      entityId: '123',
      previousState: { value: 'old' },
      newState: { value: 'new' },
      changedFields: ['value'],
    });

    // Log a system event
    await this.auditService.logSystemEvent('SCHEDULED_JOB_COMPLETED', {
      jobName: 'cleanup',
      recordsProcessed: 100,
    });

    // Log an error
    await this.auditService.logError('PaymentProcessor', 'Payment failed', {
      orderId: '456',
    });

    // Log access denied
    await this.auditService.logAccessDenied('AdminPanel', undefined, 'Insufficient permissions');
  }
}
```

## API Endpoints

All endpoints require JWT authentication.

### Audit Logs

| Method | Endpoint                              | Description                   |
| ------ | ------------------------------------- | ----------------------------- |
| GET    | `/audit/logs`                         | Query audit logs with filters |
| GET    | `/audit/logs/:id`                     | Get a specific audit log      |
| GET    | `/audit/logs/:id/verify`              | Verify audit log integrity    |
| GET    | `/audit/entity/:entityType/:entityId` | Get history for an entity     |
| GET    | `/audit/user/:userId`                 | Get user's activity           |
| GET    | `/audit/me/activity`                  | Get current user's activity   |
| GET    | `/audit/statistics`                   | Get audit statistics          |

### Query Parameters

| Parameter       | Type        | Description                               |
| --------------- | ----------- | ----------------------------------------- |
| `tenantId`      | string      | Filter by tenant                          |
| `userId`        | string      | Filter by user                            |
| `entityType`    | string      | Filter by entity type                     |
| `entityId`      | string      | Filter by entity ID                       |
| `action`        | AuditAction | Filter by action type                     |
| `correlationId` | string      | Filter by correlation ID                  |
| `startDate`     | ISO date    | Filter logs after this date               |
| `endDate`       | ISO date    | Filter logs before this date              |
| `page`          | number      | Page number (default: 1)                  |
| `limit`         | number      | Results per page (default: 50, max: 100)  |
| `sortBy`        | string      | Sort field: createdAt, action, entityType |
| `sortOrder`     | string      | asc or desc                               |

### Retention Policies

| Method | Endpoint                                | Description                 |
| ------ | --------------------------------------- | --------------------------- |
| GET    | `/audit/retention/policies`             | List retention policies     |
| GET    | `/audit/retention/policies/:id`         | Get a policy                |
| POST   | `/audit/retention/policies`             | Create a policy             |
| PUT    | `/audit/retention/policies/:id`         | Update a policy             |
| DELETE | `/audit/retention/policies/:id`         | Delete a policy             |
| POST   | `/audit/retention/policies/:id/execute` | Execute a policy manually   |
| GET    | `/audit/retention/stats`                | Get retention statistics    |
| POST   | `/audit/retention/cleanup`              | Manual cleanup (admin only) |

## Retention Policy Configuration

```typescript
{
  name: "Default 90-day retention",
  tenantId: null,          // null = applies globally
  retentionDays: 90,
  entityTypes: [],         // empty = all entity types
  actions: [],             // empty = all actions
  archiveEnabled: true,
  archiveLocation: "s3://bucket/audit-archives"
}
```

Retention policies run automatically at 2 AM daily via cron job.

## Audit Actions

| Action          | Description      |
| --------------- | ---------------- |
| `CREATE`        | Entity created   |
| `READ`          | Entity read      |
| `UPDATE`        | Entity updated   |
| `DELETE`        | Entity deleted   |
| `LOGIN`         | User login       |
| `LOGOUT`        | User logout      |
| `EXPORT`        | Data exported    |
| `IMPORT`        | Data imported    |
| `SYSTEM_EVENT`  | System event     |
| `API_CALL`      | Generic API call |
| `ERROR`         | Error occurred   |
| `ACCESS_DENIED` | Access denied    |
| `DATA_CHANGE`   | Data modified    |

## Sensitive Data Handling

The following fields are automatically redacted in audit logs:

- password, token, secret
- apiKey, refreshToken, accessToken
- ssn, creditCard, cvv

Additional sensitive fields can be specified per-endpoint:

```typescript
@Audit({ entityType: 'Payment', sensitiveFields: ['cardNumber', 'bankAccount'] })
```

## Database Schema

The audit module adds two tables:

- `audit_logs` - Main audit log storage
- `audit_retention_policies` - Retention policy configuration

Run Prisma migration to create the tables:

```bash
npx prisma migrate dev --name add-audit-logging
```
