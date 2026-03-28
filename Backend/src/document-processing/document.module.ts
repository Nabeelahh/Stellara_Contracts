import { Module } from '@nestjs/common';
import { DocumentService } from './document.service';
import { DocumentController } from './document.controller';
import { DocumentWebhookController } from './webhook.controller';
import { PrismaService } from '../prisma.service';

@Module({
  providers: [DocumentService, PrismaService],
  controllers: [DocumentController, DocumentWebhookController],
  exports: [DocumentService],
})
export class DocumentProcessingModule {}
