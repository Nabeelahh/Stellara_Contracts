import { Controller, Post, UploadedFile, UseInterceptors, Get, Param, Body } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { DocumentService } from './document.service';

@Controller('documents')
export class DocumentController {
  constructor(private readonly service: DocumentService) {}

  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  async upload(@UploadedFile() file: Express.Multer.File) {
    if (!file) return { error: 'no_file' };
    const { documentId } = await this.service.saveFile(file.originalname, file.buffer);
    return { documentId, filename: file.originalname, status: 'queued' };
  }

  @Get(':id/status')
  async status(@Param('id') id: string) {
    return { documentId: id, status: this.service.getStatus(id) };
  }

  @Get(':id/result')
  async result(@Param('id') id: string) {
    const r = this.service.getResult(id);
    if (!r) return { documentId: id, status: this.service.getStatus(id) };
    return r;
  }

  @Post(':id/verify')
  async verify(@Param('id') id: string, @Body() body: { reviewer: string; comments?: string; updates?: any }) {
    // in prod: record reviewer actions and optionally apply updates to extracted fields
    await this.service.writeAudit(id, 'human_verify', body);
    return { status: 'ok' };
  }
}
