# Database Migration Guide

## Daily Development Workflow

```bash
# 1. Modify prisma/schema.prisma
# 2. Generate and apply migration locally
npm run db:migrate              # creates migration + applies it

# 3. If you only want to create the SQL file without applying
npm run db:migrate:create       # review the SQL in prisma/migrations/

# 4. Check current status
npm run db:migrate:status

# 5. Regenerate client after schema changes
npm run db:generate
```

## Rollback Procedures

```bash
# List all applied migrations
npm run db:rollback:list

# Roll back the last migration
npm run db:rollback -- --steps 1

# Roll back to a specific migration
npm run db:rollback -- --target 20240101000000_init

# After rollback, re-apply from current state
npm run db:migrate:deploy
```

> Prisma does not generate automatic down migrations. The rollback script
> resets the `public` schema, re-applies only the migrations that should stay,
> and leaves the rolled-back migration folders ready for a later
> `migrate deploy`. For destructive data rollbacks, write a new migration that
> explicitly restores the old shape and data.

## Seed Data

```bash
# Run seed (safe to run multiple times - uses upsert)
npm run db:seed
```

Seed runs automatically after `prisma migrate reset`.

## CI/CD Pipeline

The `db-migrations.yml` workflow runs on every PR touching `prisma/`:

| Job               | Trigger         | What it does                                       |
| ----------------- | --------------- | -------------------------------------------------- |
| validate          | PR / push       | Applies migrations to a fresh DB, checks for drift |
| seed-test         | After validate  | Runs seed script against migrated DB               |
| rollback-test     | After validate  | Tests rollback + re-apply cycle                    |
| deploy-staging    | Push to main    | Deploys to staging environment                     |
| deploy-production | Manual dispatch | Deploys to production (requires staging success)   |

The blue-green release workflow lives at `.github/workflows/backend-blue-green.yml`.

Required GitHub secrets:

- `STAGING_DATABASE_URL`
- `PRODUCTION_DATABASE_URL`

## Production Deployment Checklist

### Before deploying

- [ ] All migrations committed and reviewed in PR
- [ ] `npm run db:migrate:status` shows no drift locally
- [ ] New migrations are additive (no column drops, no renames without compatibility shim)
- [ ] If removing a column: deploy app code that stops using it first, then drop in a follow-up migration
- [ ] Database backup taken (or automated backup confirmed)
- [ ] Staging migration ran successfully
- [ ] Candidate blue-green slot is healthy before any traffic switch
- [ ] Risky changes are hidden behind feature flags during rollout

### Zero-downtime migration rules

1. Never rename a column directly - add new column, backfill, update app, drop old column.
2. Never add a NOT NULL column without a default value.
3. Never drop a column that the current app version still reads.
4. Index creation should use `CREATE INDEX CONCURRENTLY` in raw SQL migrations.
5. Contract migrations only after the old slot has been fully drained.

### Deploying

```bash
# Run pre-deploy safety check
npm run db:pre-deploy

# Apply migrations (idempotent - safe to re-run)
npm run db:migrate:deploy

# Promote the inactive slot with health gates and automatic rollback
npm run deploy:blue-green
```

### After deploying

- [ ] `npm run db:migrate:status` shows all migrations applied
- [ ] Application health check passes
- [ ] Key user flows smoke-tested
- [ ] Monitor error rates for 15 minutes post-deploy

### Emergency rollback

```bash
# 0. Return traffic to the stable slot
npm run deploy:rollback

# 1. Identify the bad migration
npm run db:rollback:list

# 2. Roll it back
npm run db:rollback -- --steps 1

# 3. Redeploy previous app version
# 4. Re-apply migrations once fix is ready
npm run db:migrate:deploy
```
