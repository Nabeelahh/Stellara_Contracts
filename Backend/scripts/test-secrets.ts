// scripts/test-secrets.ts
import { SecretsManagerClient, CreateSecretCommand, DescribeSecretCommand } from '@aws-sdk/client-secrets-manager';

async function testSecretsManager() {
  console.log('🧪 Testing AWS Secrets Manager connection...');

  const client = new SecretsManagerClient({
    region: process.env.AWS_REGION || 'us-east-1',
  });

  try {
    // Test creating a secret
    const testSecretName = 'stellara/test-secret';
    const testData = { test: 'value', timestamp: new Date().toISOString() };

    console.log('📝 Creating test secret...');
    await client.send(new CreateSecretCommand({
      Name: testSecretName,
      SecretString: JSON.stringify(testData),
      Description: 'Test secret for secrets management system',
    }));

    console.log('✅ Test secret created successfully');

    // Test retrieving the secret
    console.log('📖 Retrieving test secret...');
    const response = await client.send(new DescribeSecretCommand({
      SecretId: testSecretName,
    }));

    console.log('✅ Test secret retrieved successfully');
    console.log('🔍 Secret details:', {
      name: response.Name,
      arn: response.ARN,
      createdDate: response.CreatedDate,
      description: response.Description,
    });

    console.log('🎉 AWS Secrets Manager connection test passed!');
    console.log('');
    console.log('📋 Next steps:');
    console.log('1. Run database migrations: npm run db:migrate');
    console.log('2. Start the application: npm run start:dev');
    console.log('3. Run the full setup: npm run secrets:setup');

  } catch (error) {
    console.error('❌ AWS Secrets Manager test failed:', error.message);

    if (error.name === 'InvalidAccessKeyId') {
      console.log('💡 Solution: Configure AWS credentials');
      console.log('   export AWS_ACCESS_KEY_ID=your-access-key');
      console.log('   export AWS_SECRET_ACCESS_KEY=your-secret-key');
      console.log('   export AWS_REGION=us-east-1');
    } else if (error.name === 'AccessDeniedException') {
      console.log('💡 Solution: Check IAM permissions for Secrets Manager');
    } else if (error.name === 'RegionNotFoundException') {
      console.log('💡 Solution: Set a valid AWS region');
    }

    process.exit(1);
  }
}

// Run the test if this script is executed directly
if (require.main === module) {
  testSecretsManager().catch(console.error);
}

export { testSecretsManager };