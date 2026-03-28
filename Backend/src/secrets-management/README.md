# Secrets Management System

This directory contains the comprehensive secrets management system for Stellara, providing centralized secret storage, automated rotation, access auditing, and runtime configuration retrieval.

## Overview

The secrets management system integrates with AWS Secrets Manager to provide:

- **Centralized Secret Storage**: All sensitive data stored securely in AWS Secrets Manager
- **Automated Rotation**: Scheduled rotation of secrets (database passwords every 30 days, API keys every 90 days)
- **Access Auditing**: Comprehensive logging and anomaly detection for secret access
- **Runtime Configuration**: Secrets retrieved at runtime without environment variables
- **Emergency Operations**: Immediate secret revocation and rotation capabilities
- **Versioning & Rollback**: Secret versioning with rollback capabilities

## Architecture

### Core Components

- **`secrets-management.service.ts`**: Core service for AWS Secrets Manager integration
- **`secret-access-logger.service.ts`**: Access auditing and anomaly detection
- **`secret-rotation.service.ts`**: Automated and manual rotation management
- **`secrets-management.controller.ts`**: REST API endpoints
- **`config-with-secrets.service.ts`**: Runtime configuration service
- **`secrets-management.module.ts`**: NestJS module configuration

### Database Models

- **`Secret`**: Central secret registry with rotation schedules
- **`SecretVersion`**: Version history with AWS version IDs
- **`SecretAccessLog`**: Comprehensive access auditing
- **`SecretRotation`**: Rotation history and status
- **`SecretAlert`**: Security alerts for unusual patterns

## Setup

### Prerequisites

1. AWS account with Secrets Manager access
2. IAM permissions for Secrets Manager operations
3. Database migrations applied

### Initial Setup

1. **Configure AWS Credentials**:
   ```bash
   # Set AWS credentials (or use IAM roles)
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_REGION=us-east-1
   ```

2. **Run Database Migrations**:
   ```bash
   npm run db:migrate
   ```

3. **Initialize Secrets**:
   ```bash
   npm run secrets:setup
   ```

   This will create initial secrets for:
   - Database credentials (`stellara/database`)
   - JWT secrets (`stellara/jwt`)
   - Stripe keys (`stellara/stripe`)
   - Twilio credentials (`stellara/twilio`)
   - AWS credentials (`stellara/aws`)
   - SendGrid API key (`stellara/sendgrid`)

## Usage

### Runtime Configuration

Replace environment variables with runtime secret retrieval:

```typescript
// Before (environment variables)
const dbConfig = {
  host: process.env.DATABASE_HOST,
  password: process.env.DATABASE_PASSWORD,
  // ...
};

// After (runtime retrieval)
import { ConfigWithSecretsService } from './secrets-management/config-with-secrets.service';

@Injectable()
export class MyService {
  constructor(private configService: ConfigWithSecretsService) {}

  async getDatabaseConfig() {
    return this.configService.getConfig('database');
  }
}
```

### API Endpoints

#### Secret Management
- `GET /secrets-management/secrets` - List all secrets
- `GET /secrets-management/secrets/:name` - Get secret details
- `POST /secrets-management/secrets` - Create new secret
- `PUT /secrets-management/secrets/:name` - Update secret
- `DELETE /secrets-management/secrets/:name` - Delete secret

#### Rotation Operations
- `POST /secrets-management/secrets/:name/rotate` - Rotate specific secret
- `POST /secrets-management/secrets/rotate/bulk` - Bulk rotation by type
- `POST /secrets-management/secrets/rotate/emergency` - Emergency rotation of all secrets

#### Monitoring & Auditing
- `GET /secrets-management/access-logs` - Access logs with filtering
- `GET /secrets-management/alerts` - Security alerts
- `GET /secrets-management/rotation-history` - Rotation history
- `GET /secrets-management/statistics` - Access statistics and analytics

### Manual Operations

#### Rotate a Specific Secret
```bash
curl -X POST http://localhost:3000/secrets-management/secrets/stellara/database/rotate \
  -H "Content-Type: application/json" \
  -d '{"reason": "Manual rotation"}'
```

#### Emergency Revocation
```bash
curl -X POST http://localhost:3000/secrets-management/secrets/revoke/emergency \
  -H "Content-Type: application/json" \
  -d '{"reason": "Security breach detected"}'
```

#### Check Access Logs
```bash
curl "http://localhost:3000/secrets-management/access-logs?secretName=stellara/database&limit=50"
```

## Configuration

### Rotation Schedules

Configure rotation intervals in the secret metadata:

```typescript
await secretsService.putSecret(
  'stellara/database',
  secretData,
  'database',
  'Database credentials',
  '30d', // Rotate every 30 days
  'admin'
);
```

Supported intervals:
- `'30d'` - 30 days
- `'90d'` - 90 days
- `'never'` - Manual rotation only

### Anomaly Detection

Configure anomaly detection thresholds in `secret-access-logger.service.ts`:

```typescript
private readonly ANOMALY_THRESHOLDS = {
  requestsPerHour: 100,      // Alert if > 100 requests/hour
  uniqueIPsPerHour: 10,      // Alert if > 10 unique IPs/hour
  failedRequestsRatio: 0.1,  // Alert if > 10% failures
};
```

## Security Features

### Access Control
- Secrets are encrypted at rest in AWS Secrets Manager
- Access logging for all secret operations
- Role-based access control (configurable)

### Anomaly Detection
- Statistical analysis of access patterns
- Automated alerts for unusual activity
- Configurable thresholds for different secret types

### Emergency Operations
- Immediate secret revocation
- Bulk rotation capabilities
- Audit trails for all emergency operations

### Versioning & Rollback
- Automatic versioning on rotation
- Rollback to previous versions
- Version history retention

## Monitoring

### Metrics
- Secret access frequency
- Rotation success/failure rates
- Anomaly detection alerts
- Emergency operation logs

### Alerts
- Unusual access patterns
- Rotation failures
- Emergency operations
- Secret expiration warnings

## Best Practices

### Development
1. Never commit secrets to version control
2. Use different secrets for each environment
3. Rotate secrets regularly, even in development
4. Test rotation procedures regularly

### Production
1. Use IAM roles instead of access keys
2. Enable CloudTrail for audit logging
3. Set up monitoring and alerting
4. Implement backup and recovery procedures
5. Regularly review access logs

### Security
1. Implement least-privilege access
2. Monitor for unusual access patterns
3. Have emergency response procedures
4. Regularly audit secret usage
5. Implement secret rotation policies

## Troubleshooting

### Common Issues

#### AWS Credentials
```
Error: Unable to locate credentials
```
**Solution**: Configure AWS credentials or IAM roles properly.

#### Secret Not Found
```
Error: Secret not found: stellara/database
```
**Solution**: Run `npm run secrets:setup` to initialize secrets.

#### Rotation Failed
```
Error: Rotation failed for secret: stellara/database
```
**Solution**: Check AWS permissions and secret configuration.

#### Database Connection Failed
```
Error: Authentication failed
```
**Solution**: Verify database secret is properly configured and rotated.

### Logs and Debugging

Enable debug logging:
```bash
export DEBUG=secrets-management:*
```

Check application logs:
```bash
tail -f logs/application.log | grep secrets-management
```

## API Reference

### Secret Object
```typescript
interface Secret {
  id: string;
  name: string;
  type: string;
  description: string;
  rotationInterval: string;
  nextRotation: Date;
  lastRotated: Date;
  isActive: boolean;
  emergencyRevoked: boolean;
  createdAt: Date;
  updatedAt: Date;
}
```

### Access Log Entry
```typescript
interface SecretAccessLog {
  id: string;
  secretId: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  errorMessage?: string;
  accessedAt: Date;
  metadata: Record<string, any>;
}
```

### Alert Object
```typescript
interface SecretAlert {
  id: string;
  secretId: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  metadata: Record<string, any>;
  resolved: boolean;
  createdAt: Date;
}
```

## Contributing

When adding new secret types:

1. Update the `SecretType` enum in the database schema
2. Add rotation logic in `SecretRotationService`
3. Update the setup script with default values
4. Add configuration retrieval in `ConfigWithSecretsService`
5. Update this documentation

## License

This module is part of the Stellara backend services.