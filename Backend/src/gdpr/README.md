# GDPR Compliance Implementation

## Overview
This implementation provides comprehensive GDPR compliance features for the Stellara Contracts Backend system, including data export, deletion rights, consent management, and retention policies.

## Features Implemented

### 1. Data Export Service
- **Location**: `src/gdpr/services/data-export.service.ts`
- **Capabilities**:
  - Export complete user data in JSON or CSV format
  - Aggregates data from User, WalletBinding, RefreshToken, ApiToken, AuditLog, and Consent entities
  - Rate limiting and request tracking
  - Comprehensive audit logging

### 2. Data Deletion Service
- **Location**: `src/gdpr/services/data-deletion.service.ts`
- **Capabilities**:
  - Soft deletion with 30-day retention period
  - Hard deletion workflow for expired data
  - Admin override capabilities
  - Proper audit trail for all deletion actions

### 3. Consent Management Service
- **Location**: `src/gdpr/services/consent-management.service.ts`
- **Capabilities**:
  - Track consent for different purposes (data processing, marketing, analytics, third-party sharing)
  - Consent withdrawal functionality
  - Consent history and versioning
  - Automated consent expiration
  - Consent analytics and reporting

### 4. Data Retention Service
- **Location**: `src/gdpr/services/data-retention.service.ts`
- **Capabilities**:
  - Configurable retention policies
  - Automated data cleanup jobs
  - Support for delete, archive, and anonymize actions
  - Retention statistics and monitoring

## API Endpoints

### User Endpoints
- `GET /gdpr/export` - Request data export (JSON/CSV)
- `POST /gdpr/delete-request` - Request account deletion
- `GET /gdpr/consent` - View current consent status
- `POST /gdpr/consent` - Update consent preferences
- `GET /gdpr/deletion-status` - Check deletion status

### Admin Endpoints
- `GET /admin/gdpr/requests` - View pending deletion requests
- `POST /admin/gdpr/process-deletion/:requestId` - Process deletion
- `POST /admin/gdpr/cancel-deletion/:userId` - Cancel deletion
- `GET /admin/gdpr/consent-reports` - Consent analytics
- `POST /admin/gdpr/update-consent-version` - Update consent version
- `POST /admin/gdpr/retention-cleanup` - Execute retention cleanup
- `GET /admin/gdpr/retention-policies` - View retention policies
- `GET /admin/gdpr/retention-statistics` - View retention statistics
- `POST /admin/gdpr/expire-consents` - Expire outdated consents

## Database Schema

### Consent Entity
```sql
CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    userId UUID NOT NULL,
    consentType VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'granted',
    version VARCHAR(50) NOT NULL,
    consentText TEXT,
    grantedAt TIMESTAMP DEFAULT NOW(),
    withdrawnAt TIMESTAMP,
    expiresAt TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT NOW()
);
```

## Security Features
- All requests require proper authentication
- Admin actions are logged in audit trail
- Rate limiting to prevent abuse
- Data encryption in transit and at rest
- Secure temporary file handling

## Retention Policies
- **Audit Logs**: 2 years
- **Consents**: 5 years
- **Inactive Users**: 30 days
- **System Logs**: 90 days

## Testing
Unit tests are included in `src/gdpr/gdpr.spec.ts` covering all major services:
- Data export functionality
- Deletion request processing
- Consent management
- Retention policy handling

## Integration Points
- **Audit Module**: All actions are logged for compliance
- **Auth Module**: User authentication and authorization
- **Database**: PostgreSQL with TypeORM entities

## Usage Examples

### Requesting Data Export
```bash
curl -X GET "http://localhost:3000/gdpr/export?format=json" \
  -H "Authorization: Bearer <user-jwt-token>"
```

### Granting Consent
```bash
curl -X POST "http://localhost:3000/gdpr/consent" \
  -H "Authorization: Bearer <user-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "consentType": "data_processing",
    "granted": true,
    "version": "1.0.0"
  }'
```

### Admin Processing Deletion
```bash
curl -X POST "http://localhost:3000/admin/gdpr/process-deletion/del_1234567890_user123" \
  -H "Authorization: Bearer <admin-jwt-token>"
```

## Compliance Notes
This implementation addresses key GDPR requirements:
- ✅ Right to data portability (Article 20)
- ✅ Right to erasure (Article 17)
- ✅ Consent management (Article 7)
- ✅ Data retention policies (Article 5)
- ✅ Audit logging for compliance
- ✅ Secure data handling