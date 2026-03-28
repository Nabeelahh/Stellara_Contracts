import 'dotenv/config';

import { defineConfig } from 'prisma/config';

// Prisma v7: database connection URL is configured here instead of schema.prisma
// See: https://pris.ly/d/config-datasource

export default defineConfig({
  earlyAccess: true,
  schema: './prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: process.env['DATABASE_URL'],
    shadowDatabaseUrl: process.env['SHADOW_DATABASE_URL'],
  },
});
