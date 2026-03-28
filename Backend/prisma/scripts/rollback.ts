/**
 * Migration Rollback Script
 *
 * Prisma Migrate does not support automatic down migrations.
 * This script provides a controlled rollback by:
 *   1. Listing applied migrations
 *   2. Marking the last N migrations as rolled back in _prisma_migrations
 *   3. Dropping the schema and re-applying up to the target migration
 *
 * Usage:
 *   npx ts-node prisma/scripts/rollback.ts --steps 1
 *   npx ts-node prisma/scripts/rollback.ts --target 20240101000000_init
 *
 * WARNING: This is destructive. Always back up your database first.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { createPrismaClient } from '../client';
import { execSync } from 'child_process';

const prisma = createPrismaClient();
const migrationsDir = path.resolve(__dirname, '..', 'migrations');

interface MigrationRecord {
  id: string;
  migration_name: string;
  finished_at: Date | null;
  applied_steps_count: number;
}

async function getAppliedMigrations (): Promise<MigrationRecord[]> {
  const result = await prisma.$queryRaw<MigrationRecord[]>`
    SELECT id, migration_name, finished_at, applied_steps_count
    FROM _prisma_migrations
    WHERE finished_at IS NOT NULL
    ORDER BY finished_at ASC
  `;
  return result;
}

async function resetPublicSchema () {
  await prisma.$executeRawUnsafe('DROP SCHEMA IF EXISTS "public" CASCADE');
  await prisma.$executeRawUnsafe('CREATE SCHEMA "public"');
}

function moveMigrationDirectories (migrationNames: string[]) {
  if (migrationNames.length === 0) {
    return {
      tempDir: null,
      movedDirectories: [] as Array<{ source: string; destination: string }>,
    };
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'prisma-rollback-'));
  const movedDirectories = migrationNames.map((migrationName) => {
    const source = path.join(migrationsDir, migrationName);
    const destination = path.join(tempDir, migrationName);

    if (!fs.existsSync(source)) {
      throw new Error(`Migration directory not found: ${migrationName}`);
    }

    fs.renameSync(source, destination);
    return { source, destination };
  });

  return { tempDir, movedDirectories };
}

function restoreMigrationDirectories (
  movedDirectories: Array<{ source: string; destination: string }>,
  tempDir: string | null,
) {
  for (const { source, destination } of movedDirectories.reverse()) {
    if (fs.existsSync(destination)) {
      fs.renameSync(destination, source);
    }
  }

  if (tempDir && fs.existsSync(tempDir)) {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function reapplyRemainingMigrations () {
  execSync('npx prisma migrate deploy', {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
  });
}

async function rollbackSteps (steps: number) {
  const migrations = await getAppliedMigrations();

  if (migrations.length === 0) {
    console.log('No applied migrations found.');
    return;
  }

  if (steps > migrations.length) {
    console.error(
      `❌ Cannot roll back ${steps} migration(s); only ${migrations.length} applied migration(s) found`,
    );
    process.exit(1);
  }

  const toRollback = migrations.slice(-steps);
  const remaining = migrations.slice(0, -steps);
  console.log(`\n⚠️  Rolling back ${steps} migration(s):`);
  toRollback
    .slice()
    .reverse()
    .forEach((m) => console.log(`  - ${m.migration_name}`));

  if (process.env.NODE_ENV === 'production') {
    console.error('❌ Rollback in production requires ALLOW_PRODUCTION_ROLLBACK=true');
    if (process.env.ALLOW_PRODUCTION_ROLLBACK !== 'true') process.exit(1);
  }

  const rolledBackMigrationNames = toRollback.map((migration) => migration.migration_name);
  const { tempDir, movedDirectories } = moveMigrationDirectories(rolledBackMigrationNames);

  try {
    await resetPublicSchema();
    console.log('  ✅ Reset public schema');

    if (remaining.length > 0) {
      reapplyRemainingMigrations();
      console.log(`  ✅ Re-applied ${remaining.length} remaining migration(s)`);
    } else {
      console.log('  ✅ No remaining migrations to re-apply');
    }
  } finally {
    restoreMigrationDirectories(movedDirectories, tempDir);
  }

  console.log(
    '\n📋 Rolled-back migrations are available to re-apply on next `prisma migrate deploy`',
  );
  console.log('   Run: npm run db:migrate:deploy to re-apply from the current rollback point\n');
}

async function rollbackToTarget (targetMigration: string) {
  const migrations = await getAppliedMigrations();
  const targetIndex = migrations.findIndex((m) => m.migration_name.includes(targetMigration));

  if (targetIndex === -1) {
    console.error(`❌ Migration "${targetMigration}" not found in applied migrations`);
    process.exit(1);
  }

  const steps = migrations.length - targetIndex - 1;

  if (steps === 0) {
    console.log(
      `Migration "${migrations[targetIndex].migration_name}" is already the current migration.`,
    );
    return;
  }

  await rollbackSteps(steps);
}

async function listMigrations () {
  const migrations = await getAppliedMigrations();
  console.log('\n📋 Applied migrations (newest first):');
  migrations
    .slice()
    .reverse()
    .forEach((m, i) => {
      console.log(`  ${i + 1}. ${m.migration_name} (applied: ${m.finished_at?.toISOString()})`);
    });
  console.log('');
}

async function main () {
  const args = process.argv.slice(2);

  if (args.includes('--list')) {
    await listMigrations();
    return;
  }

  const stepsFlag = args.indexOf('--steps');
  const targetFlag = args.indexOf('--target');

  if (stepsFlag !== -1) {
    const steps = parseInt(args[stepsFlag + 1], 10);
    if (isNaN(steps) || steps < 1) {
      console.error('❌ --steps must be a positive integer');
      process.exit(1);
    }
    await rollbackSteps(steps);
  } else if (targetFlag !== -1) {
    const target = args[targetFlag + 1];
    if (!target) {
      console.error('❌ --target requires a migration name');
      process.exit(1);
    }
    await rollbackToTarget(target);
  } else {
    console.log('Usage:');
    console.log('  --list                    List all applied migrations');
    console.log('  --steps <n>               Roll back last n migrations');
    console.log('  --target <migration_name> Roll back to a specific migration');
  }
}

main()
  .catch((e) => {
    console.error('❌ Rollback failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
