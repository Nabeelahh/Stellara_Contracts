import 'dotenv/config';

import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';

function getDatabaseUrl (): string {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
        throw new Error('DATABASE_URL is not set');
    }
    return databaseUrl;
}

export function getPrismaClientOptions () {
    return {
        adapter: new PrismaPg({ connectionString: getDatabaseUrl() }),
    };
}

export function createPrismaClient () {
    return new PrismaClient(getPrismaClientOptions());
}
