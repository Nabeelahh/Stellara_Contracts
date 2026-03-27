import { Module } from '@nestjs/common';
import { VestingService } from './vesting.service';
import { VestingController } from './vesting.controller';
import { PrismaService } from '../prisma.service';

@Module({
  controllers: [VestingController],
  providers: [VestingService, PrismaService],
  exports: [VestingService],
})
export class VestingModule {}
