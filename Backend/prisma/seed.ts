import { Role } from '@prisma/client';
import { createPrismaClient } from './client';

const prisma = createPrismaClient();

async function main () {
  console.log('🌱 Seeding database...');

  // Seed default categories
  const categories = [
    { name: 'Technology', description: 'Tech and software projects' },
    { name: 'Healthcare', description: 'Medical and health-related projects' },
    { name: 'Education', description: 'Educational initiatives' },
    { name: 'Environment', description: 'Environmental and sustainability projects' },
    { name: 'Arts & Culture', description: 'Creative and cultural projects' },
    { name: 'Social Impact', description: 'Community and social good projects' },
  ];

  for (const category of categories) {
    await prisma.category.upsert({
      where: { name: category.name },
      update: {},
      create: category,
    });
  }
  console.log(`✅ Seeded ${categories.length} categories`);

  // Seed a super admin user (dev/staging only)
  if (process.env.NODE_ENV !== 'production') {
    const adminUser = await prisma.user.upsert({
      where: { walletAddress: 'GADMIN000000000000000000000000000000000000000000000000000' },
      update: {},
      create: {
        walletAddress: 'GADMIN000000000000000000000000000000000000000000000000000',
        roles: [Role.SUPER_ADMIN],
        reputationScore: 100,
        trustScore: 1000,
      },
    });
    console.log(`✅ Seeded admin user: ${adminUser.id}`);
  }

  console.log('🎉 Seeding complete');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
