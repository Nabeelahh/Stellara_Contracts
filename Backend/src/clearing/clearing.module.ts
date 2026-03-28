import { Module } from '@nestjs/common';
import { ClearingService } from './clearing.service';
import { ClearingController } from './clearing.controller';
import { PrismaService } from '../prisma.service';

@Module({
  providers: [ClearingService, PrismaService],
  controllers: [ClearingController],
  exports: [ClearingService],
})
export class ClearingModule {}
