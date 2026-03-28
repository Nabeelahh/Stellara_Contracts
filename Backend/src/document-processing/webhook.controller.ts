import { Controller, Post, Req, Res, Body, Headers } from '@nestjs/common';
import { Request, Response } from 'express';
import { DocusignAdapter } from './adapters/docusign.adapter';
import { AdobeSignAdapter } from './adapters/adobesign.adapter';
import { PrismaService } from '../prisma.service';

@Controller('documents/webhook')
export class DocumentWebhookController {
  constructor(private readonly prisma: PrismaService) {}

  @Post('docusign')
  async docusignWebhook(@Req() req: Request, @Res() res: Response, @Headers() headers, @Body() body: any) {
    try {
      const raw = JSON.stringify(body);
      if (!DocusignAdapter.validateWebhook(headers, raw)) {
        return res.status(400).send('invalid_signature');
      }

      // Process notifications (envelope events)
      await this.prisma.auditLog.create({ data: { action: 'docusign_webhook', metadata: body } });

      // Optionally fetch signed documents if envelope is completed
      // body may contain envelopeId and accountId depending on config
      const envelopeId = body?.envelopeId || body?.envelope?.envelopeId;
      const accountId = body?.accountId || process.env.DOCUSIGN_ACCOUNT_ID;
      if (envelopeId && accountId) {
        // In production iterate over documents within envelope
        // Example: fetch document id '1'
        try {
          const docBytes = await DocusignAdapter.fetchSignedDocument(accountId, envelopeId, '1');
          // persist file and create Document record
          const filename = `docusign-${envelopeId}.pdf`;
          const fs = require('fs');
          const path = require('path');
          const out = path.join(process.env.DOC_STORE_DIR || '/tmp/documents', filename);
          fs.writeFileSync(out, Buffer.from(docBytes));
          const doc = await this.prisma.document.create({ data: { filename, filepath: out, status: 'done' } });
          await this.prisma.auditLog.create({ data: { documentId: doc.id, action: 'docusign_fetched', metadata: { envelopeId } } });
        } catch (e) {
          await this.prisma.auditLog.create({ data: { action: 'docusign_fetch_failed', metadata: { envelopeId, error: String(e.message || e) } } });
        }
      }

      return res.status(200).send('ok');
    } catch (e) {
      await this.prisma.auditLog.create({ data: { action: 'docusign_webhook_error', metadata: { error: String(e.message || e) } } });
      return res.status(500).send('error');
    }
  }

  @Post('adobesign')
  async adobeWebhook(@Req() req: Request, @Res() res: Response, @Headers() headers, @Body() body: any) {
    try {
      const raw = JSON.stringify(body);
      if (!AdobeSignAdapter.validateWebhook(headers, raw)) {
        return res.status(400).send('invalid_signature');
      }

      await this.prisma.auditLog.create({ data: { action: 'adobesign_webhook', metadata: body } });

      const agreementId = body?.agreementId || body?.resource?.id;
      if (agreementId) {
        try {
          const bytes = await AdobeSignAdapter.fetchSignedAgreement(agreementId);
          const filename = `adobesign-${agreementId}.pdf`;
          const fs = require('fs');
          const path = require('path');
          const out = path.join(process.env.DOC_STORE_DIR || '/tmp/documents', filename);
          fs.writeFileSync(out, Buffer.from(bytes));
          const doc = await this.prisma.document.create({ data: { filename, filepath: out, status: 'done' } });
          await this.prisma.auditLog.create({ data: { documentId: doc.id, action: 'adobesign_fetched', metadata: { agreementId } } });
        } catch (e) {
          await this.prisma.auditLog.create({ data: { action: 'adobesign_fetch_failed', metadata: { agreementId, error: String(e.message || e) } } });
        }
      }

      return res.status(200).send('ok');
    } catch (e) {
      await this.prisma.auditLog.create({ data: { action: 'adobesign_webhook_error', metadata: { error: String(e.message || e) } } });
      return res.status(500).send('error');
    }
  }
}
