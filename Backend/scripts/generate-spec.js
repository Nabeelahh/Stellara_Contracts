'use strict';

// Register ts-node so we can import TypeScript sources directly
try {
    require('ts-node').register({
        transpileOnly: true,
        files: true,
        compilerOptions: { module: 'commonjs' },
    });
} catch (_) {
    // ts-node not available — fall back to compiled dist/
}

const { NestFactory } = require('@nestjs/core');
const { SwaggerModule, DocumentBuilder } = require('@nestjs/swagger');
const { writeFileSync, mkdirSync } = require('fs');
const { join } = require('path');

async function main() {
    // Try TypeScript source first, then compiled output
    let AppModule;
    try {
        AppModule = require('../src/app.module').AppModule;
    } catch {
        AppModule = require('../dist/app.module').AppModule;
    }

    // Silence NestJS startup noise in CI
    const app = await NestFactory.create(AppModule, { logger: false });

    const doc = SwaggerModule.createDocument(
        app,
        new DocumentBuilder()
            .setTitle('Stellara API v1')
            .setDescription('Auto-generated from NestJS decorators')
            .setVersion('1.0.0')
            .addBearerAuth(
                { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', in: 'header' },
                'JWT',
            )
            .addServer('http://localhost:3000', 'Local')
            .addServer('https://api-staging.stellara.network', 'Staging')
            .addServer('https://api.stellara.network', 'Production')
            .addTag('Auth')
            .addTag('Trading')
            .addTag('Academy')
            .addTag('Social')
            .addTag('Messaging')
            .addTag('News')
            .addTag('Health')
            .build(),
        { deepScanRoutes: true },
    );

    const outDir = join(__dirname, '..', 'specs');
    mkdirSync(outDir, { recursive: true });

    const outPath = join(outDir, 'openapi-v1.json');
    writeFileSync(outPath, JSON.stringify(doc, null, 2));
    console.log('✅  Generated', outPath);

    await app.close();
}

main().catch((err) => {
    console.error('❌  Spec generation failed:', err.message ?? err);
    process.exit(1);
});