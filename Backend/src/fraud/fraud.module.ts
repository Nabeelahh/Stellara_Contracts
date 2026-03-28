import { Module } from '@nestjs/common';
import { FraudService } from './fraud.service';
import { PrismaService } from '../prisma.service';

@Module({
  providers: [FraudService, PrismaService],
  exports: [FraudService],
})
export class FraudModule {}
