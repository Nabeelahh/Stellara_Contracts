-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "ProjectStatus" AS ENUM ('ACTIVE', 'COMPLETED', 'CANCELLED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "MilestoneStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'COMPLETED', 'FUNDED');

-- CreateEnum
CREATE TYPE "NotificationChannel" AS ENUM ('EMAIL', 'SMS', 'PUSH', 'WEBSOCKET');

-- CreateEnum
CREATE TYPE "DeliveryStatus" AS ENUM ('PENDING', 'SENT', 'FAILED', 'RETRYING');

-- CreateEnum
CREATE TYPE "NotificationType" AS ENUM ('CONTRIBUTION', 'MILESTONE', 'DEADLINE', 'SYSTEM');

-- CreateEnum
CREATE TYPE "EmailStatus" AS ENUM ('PENDING', 'SENT', 'FAILED');

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('SUPER_ADMIN', 'TENANT_ADMIN', 'USER', 'VIEWER');

-- CreateEnum
CREATE TYPE "TenantStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'DELETED', 'ARCHIVED');

-- CreateEnum
CREATE TYPE "TenantPlan" AS ENUM ('FREE', 'STARTER', 'PROFESSIONAL', 'ENTERPRISE');

-- CreateEnum
CREATE TYPE "ApiOveragePolicy" AS ENUM ('HARD_STOP', 'BILL_OVERAGE');

-- CreateEnum
CREATE TYPE "Permission" AS ENUM ('CREATE_PROJECT', 'UPDATE_PROJECT', 'DELETE_PROJECT', 'VIEW_PROJECT', 'MAKE_CONTRIBUTION', 'VIEW_CONTRIBUTION', 'MANAGE_USERS', 'MANAGE_ROLES', 'VIEW_SENSITIVE_DATA', 'MANAGE_SYSTEM');

-- CreateEnum
CREATE TYPE "CallOutcome" AS ENUM ('YES', 'NO', 'PENDING');

-- CreateEnum
CREATE TYPE "Position" AS ENUM ('YES', 'NO');

-- CreateEnum
CREATE TYPE "ResolutionStatus" AS ENUM ('PENDING', 'RESOLVED');

-- CreateEnum
CREATE TYPE "ClaimStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- CreateEnum
CREATE TYPE "TenantRole" AS ENUM ('OWNER', 'ADMIN', 'MEMBER');

-- CreateEnum
CREATE TYPE "ConfigScope" AS ENUM ('GLOBAL', 'TENANT', 'USER');

-- CreateEnum
CREATE TYPE "AuditAction" AS ENUM ('CREATE', 'READ', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'EXPORT', 'IMPORT', 'SYSTEM_EVENT', 'API_CALL', 'ERROR', 'ACCESS_DENIED', 'DATA_CHANGE');

-- CreateEnum
CREATE TYPE "SubscriptionStatus" AS ENUM ('ACTIVE', 'CANCELLED', 'PAST_DUE', 'UNPAID', 'TRIALING', 'PAUSED');

-- CreateEnum
CREATE TYPE "InvoiceStatus" AS ENUM ('DRAFT', 'OPEN', 'PAID', 'UNCOLLECTIBLE', 'VOID');

-- CreateEnum
CREATE TYPE "PaymentEventType" AS ENUM ('SUBSCRIPTION_CREATED', 'SUBSCRIPTION_UPDATED', 'SUBSCRIPTION_CANCELLED', 'INVOICE_CREATED', 'INVOICE_PAID', 'INVOICE_PAYMENT_FAILED', 'PAYMENT_METHOD_ATTACHED', 'PAYMENT_METHOD_DETACHED', 'USAGE_RECORDED', 'DUNNING_STARTED', 'DUNNING_RESOLVED', 'DUNNING_FAILED');

-- CreateEnum
CREATE TYPE "WebhookSubscriptionStatus" AS ENUM ('ACTIVE', 'PAUSED', 'DISABLED');

-- CreateEnum
CREATE TYPE "WebhookDeliveryStatus" AS ENUM ('PENDING', 'RETRYING', 'DELIVERED', 'FAILED');

-- CreateEnum
CREATE TYPE "AbiRegistryStatus" AS ENUM ('ACTIVE', 'DEPRECATED', 'ARCHIVED');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "name" TEXT,
    "wallet_address" TEXT NOT NULL,
    "profile_data" JSONB,
    "reputation_score" INTEGER NOT NULL DEFAULT 0,
    "trust_score" INTEGER NOT NULL DEFAULT 500,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "phone_number" TEXT,
    "email_encrypted" TEXT,
    "push_subscription" JSONB,
    "phone_encrypted" JSONB,
    "ssn_encrypted" JSONB,
    "address_encrypted" JSONB,
    "roles" "Role"[] DEFAULT ARRAY['USER']::"Role"[],
    "hashed_refresh_token" TEXT,
    "tenant_id" TEXT,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "projects" (
    "id" TEXT NOT NULL,
    "contract_id" TEXT NOT NULL,
    "creator_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "category" TEXT NOT NULL,
    "goal" BIGINT NOT NULL,
    "current_funds" BIGINT NOT NULL DEFAULT 0,
    "deadline" TIMESTAMP(3) NOT NULL,
    "ipfs_hash" TEXT,
    "status" "ProjectStatus" NOT NULL DEFAULT 'ACTIVE',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "projects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "contributions" (
    "id" TEXT NOT NULL,
    "transaction_hash" TEXT NOT NULL,
    "investor_id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "amount" BIGINT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "contributions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "milestones" (
    "id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "funding_amount" BIGINT NOT NULL,
    "status" "MilestoneStatus" NOT NULL DEFAULT 'PENDING',
    "completion_date" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "milestones_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reputation_history" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "score_change" INTEGER NOT NULL,
    "reason" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "reputation_history_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "categories" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "categories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ledger_cursors" (
    "id" TEXT NOT NULL,
    "network" TEXT NOT NULL,
    "last_ledger_seq" INTEGER NOT NULL,
    "last_ledger_hash" TEXT,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ledger_cursors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "processed_events" (
    "id" TEXT NOT NULL,
    "event_id" TEXT NOT NULL,
    "network" TEXT NOT NULL,
    "ledger_seq" INTEGER NOT NULL,
    "contract_id" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "transaction_hash" TEXT NOT NULL,
    "contract_type" TEXT,
    "decoded_data" JSONB,
    "abi_version" TEXT,
    "processed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "processed_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "contract_abi_registries" (
    "id" TEXT NOT NULL,
    "contract_address" TEXT NOT NULL,
    "contract_type" TEXT NOT NULL,
    "display_name" TEXT NOT NULL,
    "network" TEXT NOT NULL DEFAULT 'stellar',
    "description" TEXT,
    "status" "AbiRegistryStatus" NOT NULL DEFAULT 'ACTIVE',
    "current_version" TEXT,
    "metadata" JSONB,
    "created_by" TEXT,
    "updated_by" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "contract_abi_registries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "contract_abi_versions" (
    "id" TEXT NOT NULL,
    "registry_id" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "is_current" BOOLEAN NOT NULL DEFAULT false,
    "is_deprecated" BOOLEAN NOT NULL DEFAULT false,
    "abi_schema" JSONB NOT NULL,
    "contract_schema" JSONB NOT NULL,
    "function_schemas" JSONB NOT NULL,
    "event_schemas" JSONB NOT NULL,
    "changelog" TEXT,
    "compatibility" JSONB,
    "created_by" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "contract_abi_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "indexer_logs" (
    "id" TEXT NOT NULL,
    "level" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "indexer_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_settings" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "email_enabled" BOOLEAN NOT NULL DEFAULT true,
    "push_enabled" BOOLEAN NOT NULL DEFAULT false,
    "sms_enabled" BOOLEAN NOT NULL DEFAULT false,
    "websocket_enabled" BOOLEAN NOT NULL DEFAULT true,
    "notify_contributions" BOOLEAN NOT NULL DEFAULT true,
    "notify_milestones" BOOLEAN NOT NULL DEFAULT true,
    "notify_deadlines" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "notification_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notifications" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "type" "NotificationType" NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "read" BOOLEAN NOT NULL DEFAULT false,
    "data" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_deliveries" (
    "id" TEXT NOT NULL,
    "notification_id" TEXT NOT NULL,
    "channel" "NotificationChannel" NOT NULL,
    "status" "DeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "error_message" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_attempt_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "notification_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "email_outbox" (
    "id" TEXT NOT NULL,
    "to" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "html" TEXT NOT NULL,
    "status" "EmailStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_error" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "email_outbox_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tenants" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "status" "TenantStatus" NOT NULL DEFAULT 'ACTIVE',
    "plan" "TenantPlan" NOT NULL DEFAULT 'FREE',
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tenant_settings" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "max_users" INTEGER NOT NULL DEFAULT 10,
    "max_projects" INTEGER NOT NULL DEFAULT 5,
    "api_calls_per_month_limit" INTEGER NOT NULL DEFAULT 100000,
    "storage_gb_limit" INTEGER NOT NULL DEFAULT 100,
    "api_overage_policy" "ApiOveragePolicy" NOT NULL DEFAULT 'HARD_STOP',
    "allow_public_projects" BOOLEAN NOT NULL DEFAULT true,
    "notifications_enabled" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tenant_audit_logs" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "actor_id" TEXT,
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "token_blacklist" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "token_blacklist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "encryption_audit_logs" (
    "id" TEXT NOT NULL,
    "key_id" TEXT NOT NULL,
    "user_id" TEXT,
    "action" TEXT NOT NULL,
    "field_name" TEXT,
    "table_name" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ip_address" TEXT NOT NULL,
    "user_agent" TEXT,
    "success" BOOLEAN NOT NULL DEFAULT false,
    "error_message" TEXT,
    "processing_time_ms" INTEGER NOT NULL,

    CONSTRAINT "encryption_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "calls" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "outcome" "CallOutcome" NOT NULL DEFAULT 'PENDING',
    "resolvedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "calls_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "stake_ledger" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "callId" TEXT NOT NULL,
    "userAddress" TEXT NOT NULL,
    "amount" DECIMAL(18,4) NOT NULL,
    "position" "Position" NOT NULL,
    "profitLoss" DECIMAL(18,4),
    "transactionHash" TEXT,
    "resolutionStatus" "ResolutionStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "stake_ledger_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "claims" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "poolId" TEXT,
    "userAddress" TEXT NOT NULL,
    "amount" DECIMAL(18,4) NOT NULL,
    "status" "ClaimStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "claims_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pools" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "totalCapacity" DECIMAL(18,4) NOT NULL DEFAULT 0,
    "lockedAmount" DECIMAL(18,4) NOT NULL DEFAULT 0,
    "availableLiquidity" DECIMAL(18,4) NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "pools_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tenant_members" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" "TenantRole" NOT NULL DEFAULT 'MEMBER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tenant_members_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "config_entries" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "scope" "ConfigScope" NOT NULL DEFAULT 'GLOBAL',
    "tenant_id" TEXT,
    "user_id" TEXT,
    "encrypted" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "config_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "feature_flags" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "tenant_id" TEXT,
    "rollout_pct" INTEGER NOT NULL DEFAULT 100,
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "feature_flags_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "config_audit_logs" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "old_value" TEXT,
    "new_value" TEXT,
    "scope" "ConfigScope" NOT NULL,
    "tenant_id" TEXT,
    "actor_id" TEXT,
    "action" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "config_audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_subscriptions" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "url" TEXT NOT NULL,
    "secret" TEXT NOT NULL,
    "status" "WebhookSubscriptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "event_filters" JSONB NOT NULL,
    "payload_fields" JSONB,
    "custom_headers" JSONB,
    "created_by" TEXT,
    "last_triggered_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "webhook_subscriptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_events" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT,
    "event_type" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'platform',
    "payload" JSONB NOT NULL,
    "metadata" JSONB,
    "occurred_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "webhook_deliveries" (
    "id" TEXT NOT NULL,
    "subscription_id" TEXT NOT NULL,
    "event_id" TEXT NOT NULL,
    "status" "WebhookDeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL DEFAULT 10,
    "next_attempt_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_attempt_at" TIMESTAMP(3),
    "delivered_at" TIMESTAMP(3),
    "last_response_code" INTEGER,
    "last_response_body" TEXT,
    "error_message" TEXT,
    "signature" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "webhook_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" TEXT NOT NULL,
    "correlation_id" TEXT,
    "tenant_id" TEXT,
    "user_id" TEXT,
    "action" "AuditAction" NOT NULL,
    "entity_type" TEXT NOT NULL,
    "entity_id" TEXT,
    "method" TEXT,
    "path" TEXT,
    "status_code" INTEGER,
    "ip_address" TEXT,
    "user_agent" TEXT,
    "request_body" JSONB,
    "response_body" JSONB,
    "previous_state" JSONB,
    "new_state" JSONB,
    "changed_fields" TEXT[],
    "metadata" JSONB,
    "duration" INTEGER,
    "error_message" TEXT,
    "checksum" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_retention_policies" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "tenant_id" TEXT,
    "retention_days" INTEGER NOT NULL DEFAULT 90,
    "entity_types" TEXT[],
    "actions" TEXT[],
    "archive_enabled" BOOLEAN NOT NULL DEFAULT false,
    "archive_location" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "last_executed_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "audit_retention_policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "subscription_plans" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "stripe_price_id" TEXT NOT NULL,
    "amount" INTEGER NOT NULL,
    "currency" TEXT NOT NULL DEFAULT 'usd',
    "interval" TEXT NOT NULL DEFAULT 'month',
    "features" JSONB,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "subscription_plans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "subscriptions" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "plan_id" TEXT NOT NULL,
    "stripe_subscription_id" TEXT NOT NULL,
    "stripe_customer_id" TEXT NOT NULL,
    "status" "SubscriptionStatus" NOT NULL DEFAULT 'TRIALING',
    "current_period_start" TIMESTAMP(3) NOT NULL,
    "current_period_end" TIMESTAMP(3) NOT NULL,
    "cancel_at_period_end" BOOLEAN NOT NULL DEFAULT false,
    "canceled_at" TIMESTAMP(3),
    "trial_start" TIMESTAMP(3),
    "trial_end" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "subscriptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "usage_records" (
    "id" TEXT NOT NULL,
    "subscription_id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "metric_name" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "stripe_usage_record_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "usage_records_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "invoices" (
    "id" TEXT NOT NULL,
    "subscription_id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "stripe_invoice_id" TEXT NOT NULL,
    "status" "InvoiceStatus" NOT NULL DEFAULT 'DRAFT',
    "amount_due" INTEGER NOT NULL,
    "amount_paid" INTEGER NOT NULL DEFAULT 0,
    "currency" TEXT NOT NULL DEFAULT 'usd',
    "pdf_url" TEXT,
    "hosted_invoice_url" TEXT,
    "invoice_number" TEXT,
    "due_date" TIMESTAMP(3),
    "paid_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "invoices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "payment_methods" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "stripe_payment_method_id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "brand" TEXT,
    "last4" TEXT,
    "exp_month" INTEGER,
    "exp_year" INTEGER,
    "is_default" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "payment_methods_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "payment_events" (
    "id" TEXT NOT NULL,
    "subscription_id" TEXT,
    "tenant_id" TEXT NOT NULL,
    "event_type" "PaymentEventType" NOT NULL,
    "stripe_event_id" TEXT,
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "payment_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dunning_attempts" (
    "id" TEXT NOT NULL,
    "subscription_id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "invoice_id" TEXT NOT NULL,
    "attempt_number" INTEGER NOT NULL,
    "status" TEXT NOT NULL,
    "next_retry_at" TIMESTAMP(3),
    "email_sent_at" TIMESTAMP(3),
    "resolved_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "dunning_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_wallet_address_key" ON "users"("wallet_address");

-- CreateIndex
CREATE UNIQUE INDEX "users_phone_number_key" ON "users"("phone_number");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_encrypted_key" ON "users"("email_encrypted");

-- CreateIndex
CREATE INDEX "users_tenant_id_id_idx" ON "users"("tenant_id", "id");

-- CreateIndex
CREATE INDEX "users_tenant_id_email_encrypted_idx" ON "users"("tenant_id", "email_encrypted");

-- CreateIndex
CREATE INDEX "users_tenant_id_wallet_address_idx" ON "users"("tenant_id", "wallet_address");

-- CreateIndex
CREATE UNIQUE INDEX "users_tenant_id_email_encrypted_key" ON "users"("tenant_id", "email_encrypted");

-- CreateIndex
CREATE UNIQUE INDEX "users_tenant_id_wallet_address_key" ON "users"("tenant_id", "wallet_address");

-- CreateIndex
CREATE UNIQUE INDEX "projects_contract_id_key" ON "projects"("contract_id");

-- CreateIndex
CREATE UNIQUE INDEX "contributions_transaction_hash_key" ON "contributions"("transaction_hash");

-- CreateIndex
CREATE UNIQUE INDEX "categories_name_key" ON "categories"("name");

-- CreateIndex
CREATE UNIQUE INDEX "ledger_cursors_network_key" ON "ledger_cursors"("network");

-- CreateIndex
CREATE UNIQUE INDEX "processed_events_event_id_key" ON "processed_events"("event_id");

-- CreateIndex
CREATE INDEX "processed_events_network_ledger_seq_idx" ON "processed_events"("network", "ledger_seq");

-- CreateIndex
CREATE INDEX "processed_events_contract_id_event_type_idx" ON "processed_events"("contract_id", "event_type");

-- CreateIndex
CREATE UNIQUE INDEX "contract_abi_registries_contract_address_key" ON "contract_abi_registries"("contract_address");

-- CreateIndex
CREATE INDEX "contract_abi_registries_contract_type_network_idx" ON "contract_abi_registries"("contract_type", "network");

-- CreateIndex
CREATE INDEX "contract_abi_registries_status_updated_at_idx" ON "contract_abi_registries"("status", "updated_at");

-- CreateIndex
CREATE INDEX "contract_abi_versions_registry_id_is_current_idx" ON "contract_abi_versions"("registry_id", "is_current");

-- CreateIndex
CREATE INDEX "contract_abi_versions_version_idx" ON "contract_abi_versions"("version");

-- CreateIndex
CREATE UNIQUE INDEX "contract_abi_versions_registry_id_version_key" ON "contract_abi_versions"("registry_id", "version");

-- CreateIndex
CREATE INDEX "indexer_logs_timestamp_idx" ON "indexer_logs"("timestamp");

-- CreateIndex
CREATE INDEX "indexer_logs_level_idx" ON "indexer_logs"("level");

-- CreateIndex
CREATE UNIQUE INDEX "notification_settings_user_id_key" ON "notification_settings"("user_id");

-- CreateIndex
CREATE INDEX "notifications_user_id_idx" ON "notifications"("user_id");

-- CreateIndex
CREATE INDEX "email_outbox_status_idx" ON "email_outbox"("status");

-- CreateIndex
CREATE UNIQUE INDEX "tenants_name_key" ON "tenants"("name");

-- CreateIndex
CREATE UNIQUE INDEX "tenants_slug_key" ON "tenants"("slug");

-- CreateIndex
CREATE INDEX "tenants_status_idx" ON "tenants"("status");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_settings_tenant_id_key" ON "tenant_settings"("tenant_id");

-- CreateIndex
CREATE INDEX "tenant_audit_logs_tenant_id_idx" ON "tenant_audit_logs"("tenant_id");

-- CreateIndex
CREATE INDEX "tenant_audit_logs_action_idx" ON "tenant_audit_logs"("action");

-- CreateIndex
CREATE UNIQUE INDEX "token_blacklist_token_key" ON "token_blacklist"("token");

-- CreateIndex
CREATE INDEX "encryption_audit_logs_timestamp_idx" ON "encryption_audit_logs"("timestamp");

-- CreateIndex
CREATE INDEX "encryption_audit_logs_key_id_idx" ON "encryption_audit_logs"("key_id");

-- CreateIndex
CREATE INDEX "encryption_audit_logs_action_idx" ON "encryption_audit_logs"("action");

-- CreateIndex
CREATE INDEX "encryption_audit_logs_success_idx" ON "encryption_audit_logs"("success");

-- CreateIndex
CREATE INDEX "calls_tenantId_id_idx" ON "calls"("tenantId", "id");

-- CreateIndex
CREATE INDEX "calls_tenantId_outcome_idx" ON "calls"("tenantId", "outcome");

-- CreateIndex
CREATE INDEX "calls_tenantId_createdAt_idx" ON "calls"("tenantId", "createdAt");

-- CreateIndex
CREATE INDEX "calls_tenantId_expiresAt_idx" ON "calls"("tenantId", "expiresAt");

-- CreateIndex
CREATE INDEX "stake_ledger_tenantId_id_idx" ON "stake_ledger"("tenantId", "id");

-- CreateIndex
CREATE INDEX "stake_ledger_tenantId_callId_idx" ON "stake_ledger"("tenantId", "callId");

-- CreateIndex
CREATE INDEX "stake_ledger_tenantId_userAddress_idx" ON "stake_ledger"("tenantId", "userAddress");

-- CreateIndex
CREATE INDEX "stake_ledger_tenantId_createdAt_idx" ON "stake_ledger"("tenantId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "stake_ledger_tenantId_transactionHash_key" ON "stake_ledger"("tenantId", "transactionHash");

-- CreateIndex
CREATE INDEX "claims_tenantId_id_idx" ON "claims"("tenantId", "id");

-- CreateIndex
CREATE INDEX "claims_tenantId_poolId_idx" ON "claims"("tenantId", "poolId");

-- CreateIndex
CREATE INDEX "claims_tenantId_status_idx" ON "claims"("tenantId", "status");

-- CreateIndex
CREATE INDEX "claims_tenantId_createdAt_idx" ON "claims"("tenantId", "createdAt");

-- CreateIndex
CREATE INDEX "claims_tenantId_userAddress_idx" ON "claims"("tenantId", "userAddress");

-- CreateIndex
CREATE INDEX "pools_tenantId_id_idx" ON "pools"("tenantId", "id");

-- CreateIndex
CREATE INDEX "pools_tenantId_name_idx" ON "pools"("tenantId", "name");

-- CreateIndex
CREATE INDEX "pools_tenantId_createdAt_idx" ON "pools"("tenantId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "pools_tenantId_name_key" ON "pools"("tenantId", "name");

-- CreateIndex
CREATE INDEX "tenant_members_tenantId_role_idx" ON "tenant_members"("tenantId", "role");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_members_tenantId_userId_key" ON "tenant_members"("tenantId", "userId");

-- CreateIndex
CREATE INDEX "config_entries_scope_tenant_id_idx" ON "config_entries"("scope", "tenant_id");

-- CreateIndex
CREATE INDEX "config_entries_key_idx" ON "config_entries"("key");

-- CreateIndex
CREATE UNIQUE INDEX "config_entries_key_scope_tenant_id_user_id_key" ON "config_entries"("key", "scope", "tenant_id", "user_id");

-- CreateIndex
CREATE INDEX "feature_flags_key_idx" ON "feature_flags"("key");

-- CreateIndex
CREATE INDEX "feature_flags_tenant_id_idx" ON "feature_flags"("tenant_id");

-- CreateIndex
CREATE UNIQUE INDEX "feature_flags_key_tenant_id_key" ON "feature_flags"("key", "tenant_id");

-- CreateIndex
CREATE INDEX "config_audit_logs_key_idx" ON "config_audit_logs"("key");

-- CreateIndex
CREATE INDEX "config_audit_logs_tenant_id_idx" ON "config_audit_logs"("tenant_id");

-- CreateIndex
CREATE INDEX "config_audit_logs_created_at_idx" ON "config_audit_logs"("created_at");

-- CreateIndex
CREATE INDEX "webhook_subscriptions_tenant_id_status_idx" ON "webhook_subscriptions"("tenant_id", "status");

-- CreateIndex
CREATE INDEX "webhook_subscriptions_status_idx" ON "webhook_subscriptions"("status");

-- CreateIndex
CREATE INDEX "webhook_events_tenant_id_event_type_idx" ON "webhook_events"("tenant_id", "event_type");

-- CreateIndex
CREATE INDEX "webhook_events_event_type_occurred_at_idx" ON "webhook_events"("event_type", "occurred_at");

-- CreateIndex
CREATE INDEX "webhook_deliveries_status_next_attempt_at_idx" ON "webhook_deliveries"("status", "next_attempt_at");

-- CreateIndex
CREATE INDEX "webhook_deliveries_subscription_id_status_idx" ON "webhook_deliveries"("subscription_id", "status");

-- CreateIndex
CREATE INDEX "webhook_deliveries_event_id_idx" ON "webhook_deliveries"("event_id");

-- CreateIndex
CREATE INDEX "audit_logs_tenant_id_created_at_idx" ON "audit_logs"("tenant_id", "created_at");

-- CreateIndex
CREATE INDEX "audit_logs_user_id_created_at_idx" ON "audit_logs"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "audit_logs_entity_type_entity_id_idx" ON "audit_logs"("entity_type", "entity_id");

-- CreateIndex
CREATE INDEX "audit_logs_action_idx" ON "audit_logs"("action");

-- CreateIndex
CREATE INDEX "audit_logs_correlation_id_idx" ON "audit_logs"("correlation_id");

-- CreateIndex
CREATE INDEX "audit_logs_created_at_idx" ON "audit_logs"("created_at");

-- CreateIndex
CREATE INDEX "audit_logs_status_code_idx" ON "audit_logs"("status_code");

-- CreateIndex
CREATE UNIQUE INDEX "audit_retention_policies_name_key" ON "audit_retention_policies"("name");

-- CreateIndex
CREATE INDEX "audit_retention_policies_tenant_id_idx" ON "audit_retention_policies"("tenant_id");

-- CreateIndex
CREATE INDEX "audit_retention_policies_is_active_idx" ON "audit_retention_policies"("is_active");

-- CreateIndex
CREATE UNIQUE INDEX "subscription_plans_name_key" ON "subscription_plans"("name");

-- CreateIndex
CREATE UNIQUE INDEX "subscription_plans_stripe_price_id_key" ON "subscription_plans"("stripe_price_id");

-- CreateIndex
CREATE UNIQUE INDEX "subscriptions_tenant_id_key" ON "subscriptions"("tenant_id");

-- CreateIndex
CREATE UNIQUE INDEX "subscriptions_stripe_subscription_id_key" ON "subscriptions"("stripe_subscription_id");

-- CreateIndex
CREATE INDEX "subscriptions_tenant_id_idx" ON "subscriptions"("tenant_id");

-- CreateIndex
CREATE INDEX "subscriptions_status_idx" ON "subscriptions"("status");

-- CreateIndex
CREATE INDEX "subscriptions_stripe_customer_id_idx" ON "subscriptions"("stripe_customer_id");

-- CreateIndex
CREATE INDEX "usage_records_subscription_id_idx" ON "usage_records"("subscription_id");

-- CreateIndex
CREATE INDEX "usage_records_tenant_id_idx" ON "usage_records"("tenant_id");

-- CreateIndex
CREATE INDEX "usage_records_metric_name_idx" ON "usage_records"("metric_name");

-- CreateIndex
CREATE INDEX "usage_records_timestamp_idx" ON "usage_records"("timestamp");

-- CreateIndex
CREATE UNIQUE INDEX "invoices_stripe_invoice_id_key" ON "invoices"("stripe_invoice_id");

-- CreateIndex
CREATE INDEX "invoices_subscription_id_idx" ON "invoices"("subscription_id");

-- CreateIndex
CREATE INDEX "invoices_tenant_id_idx" ON "invoices"("tenant_id");

-- CreateIndex
CREATE INDEX "invoices_status_idx" ON "invoices"("status");

-- CreateIndex
CREATE INDEX "invoices_created_at_idx" ON "invoices"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "payment_methods_tenant_id_key" ON "payment_methods"("tenant_id");

-- CreateIndex
CREATE UNIQUE INDEX "payment_methods_stripe_payment_method_id_key" ON "payment_methods"("stripe_payment_method_id");

-- CreateIndex
CREATE INDEX "payment_methods_tenant_id_idx" ON "payment_methods"("tenant_id");

-- CreateIndex
CREATE INDEX "payment_events_subscription_id_idx" ON "payment_events"("subscription_id");

-- CreateIndex
CREATE INDEX "payment_events_tenant_id_idx" ON "payment_events"("tenant_id");

-- CreateIndex
CREATE INDEX "payment_events_event_type_idx" ON "payment_events"("event_type");

-- CreateIndex
CREATE INDEX "payment_events_created_at_idx" ON "payment_events"("created_at");

-- CreateIndex
CREATE INDEX "dunning_attempts_subscription_id_idx" ON "dunning_attempts"("subscription_id");

-- CreateIndex
CREATE INDEX "dunning_attempts_tenant_id_idx" ON "dunning_attempts"("tenant_id");

-- CreateIndex
CREATE INDEX "dunning_attempts_status_idx" ON "dunning_attempts"("status");

-- CreateIndex
CREATE INDEX "dunning_attempts_next_retry_at_idx" ON "dunning_attempts"("next_retry_at");

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_creator_id_fkey" FOREIGN KEY ("creator_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "contributions" ADD CONSTRAINT "contributions_investor_id_fkey" FOREIGN KEY ("investor_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "contributions" ADD CONSTRAINT "contributions_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "milestones" ADD CONSTRAINT "milestones_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reputation_history" ADD CONSTRAINT "reputation_history_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "contract_abi_versions" ADD CONSTRAINT "contract_abi_versions_registry_id_fkey" FOREIGN KEY ("registry_id") REFERENCES "contract_abi_registries"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_settings" ADD CONSTRAINT "notification_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_notification_id_fkey" FOREIGN KEY ("notification_id") REFERENCES "notifications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_settings" ADD CONSTRAINT "tenant_settings_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_audit_logs" ADD CONSTRAINT "tenant_audit_logs_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "calls" ADD CONSTRAINT "calls_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "stake_ledger" ADD CONSTRAINT "stake_ledger_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "stake_ledger" ADD CONSTRAINT "stake_ledger_callId_fkey" FOREIGN KEY ("callId") REFERENCES "calls"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "claims" ADD CONSTRAINT "claims_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "claims" ADD CONSTRAINT "claims_poolId_fkey" FOREIGN KEY ("poolId") REFERENCES "pools"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pools" ADD CONSTRAINT "pools_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_events" ADD CONSTRAINT "webhook_events_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_subscription_id_fkey" FOREIGN KEY ("subscription_id") REFERENCES "webhook_subscriptions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "webhook_events"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_plan_id_fkey" FOREIGN KEY ("plan_id") REFERENCES "subscription_plans"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "usage_records" ADD CONSTRAINT "usage_records_subscription_id_fkey" FOREIGN KEY ("subscription_id") REFERENCES "subscriptions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_subscription_id_fkey" FOREIGN KEY ("subscription_id") REFERENCES "subscriptions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "payment_events" ADD CONSTRAINT "payment_events_subscription_id_fkey" FOREIGN KEY ("subscription_id") REFERENCES "subscriptions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dunning_attempts" ADD CONSTRAINT "dunning_attempts_subscription_id_fkey" FOREIGN KEY ("subscription_id") REFERENCES "subscriptions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
