// scripts/setup-secrets.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { SecretsManagementService } from '../src/secrets-management/secrets-management.service';
import { SecretRotationService } from '../src/secrets-management/secret-rotation.service';

async function setupSecrets() {
  console.log('🚀 Setting up AWS Secrets Manager for Stellara...');

  const app = await NestFactory.createApplicationContext(AppModule);
  const secretsService = app.get(SecretsManagementService);
  const rotationService = app.get(SecretRotationService);

  try {
    // Database secrets
    console.log('📊 Setting up database secrets...');
    await secretsService.putSecret(
      'stellara/database',
      {
        username: process.env.DATABASE_USER || 'stellara_app',
        password: process.env.DATABASE_PASSWORD || 'change-me-in-production',
        host: process.env.DATABASE_HOST || 'localhost',
        port: parseInt(process.env.DATABASE_PORT || '5432'),
        database: process.env.DATABASE_NAME || 'stellara',
      },
      'database',
      'Database connection credentials',
      '30d', // Rotate every 30 days
      'setup-script',
    );

    // JWT secrets
    console.log('🔐 Setting up JWT secrets...');
    await secretsService.putSecret(
      'stellara/jwt',
      {
        secret: process.env.JWT_SECRET || generateSecurePassword(64),
        refreshSecret: process.env.JWT_REFRESH_SECRET || generateSecurePassword(64),
      },
      'jwt',
      'JWT signing secrets',
      '90d', // Rotate every 90 days
      'setup-script',
    );

    // Stripe secrets
    console.log('💳 Setting up Stripe secrets...');
    await secretsService.putSecret(
      'stellara/stripe',
      {
        secretKey: process.env.STRIPE_SECRET_KEY || 'sk_test_...',
        publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || 'pk_test_...',
        webhookSecret: process.env.STRIPE_WEBHOOK_SECRET || 'whsec_...',
      },
      'stripe',
      'Stripe payment processing secrets',
      '90d',
      'setup-script',
    );

    // Twilio secrets
    console.log('📱 Setting up Twilio secrets...');
    await secretsService.putSecret(
      'stellara/twilio',
      {
        accountSid: process.env.TWILIO_ACCOUNT_SID || 'AC...',
        authToken: process.env.TWILIO_AUTH_TOKEN || 'your-auth-token',
        phoneNumber: process.env.TWILIO_PHONE_NUMBER || '+1234567890',
      },
      'twilio',
      'Twilio SMS and communication secrets',
      '90d',
      'setup-script',
    );

    // AWS credentials (for the application itself)
    console.log('☁️ Setting up AWS credentials...');
    await secretsService.putSecret(
      'stellara/aws',
      {
        region: process.env.AWS_REGION || 'us-east-1',
        accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
      },
      'aws',
      'AWS credentials for application services',
      '90d',
      'setup-script',
    );

    // Additional API keys (examples)
    console.log('🔑 Setting up additional API keys...');
    await secretsService.putSecret(
      'stellara/sendgrid',
      {
        apiKey: process.env.SENDGRID_API_KEY || 'SG...',
      },
      'api_key',
      'SendGrid email service API key',
      '90d',
      'setup-script',
    );

    console.log('✅ Secrets setup completed successfully!');
    console.log('');
    console.log('📋 Next steps:');
    console.log('1. Update your environment variables to remove sensitive data');
    console.log('2. Use the secrets management API to retrieve values at runtime');
    console.log('3. Set up automated rotation schedules');
    console.log('4. Configure monitoring and alerting');
    console.log('');
    console.log('🔄 To rotate all secrets immediately, run:');
    console.log('curl -X POST http://localhost:3000/secrets-management/secrets/rotate/emergency \\');
    console.log('  -H "Content-Type: application/json" \\');
    console.log('  -d \'{"reason": "Initial setup rotation"}\'');

  } catch (error) {
    console.error('❌ Failed to setup secrets:', error.message);
    process.exit(1);
  } finally {
    await app.close();
  }
}

function generateSecurePassword(length: number): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
}

// Run the setup if this script is executed directly
if (require.main === module) {
  setupSecrets().catch(console.error);
}

export { setupSecrets };