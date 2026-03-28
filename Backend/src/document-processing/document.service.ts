import { Injectable, Logger } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import { OcrAdapter } from './ocr/ocr.adapter';
import { ExtractionResultDto, FieldExtraction } from './dto/extraction-result.dto';
import { PrismaService } from '../prisma.service';

@Injectable()
export class DocumentService {
  private readonly logger = new Logger(DocumentService.name);
  private storeDir = process.env.DOC_STORE_DIR || '/tmp/documents';

  // in-memory stores for results and status (persist to DB in prod)
  private status = new Map<string, string>();
  private results = new Map<string, ExtractionResultDto>();

  constructor(private readonly prisma?: PrismaService) {
    if (!fs.existsSync(this.storeDir)) fs.mkdirSync(this.storeDir, { recursive: true });
  }

  async saveFile(filename: string, buffer: Buffer): Promise<{ documentId: string; filepath: string }> {
    const id = uuidv4();
    const filepath = path.join(this.storeDir, `${id}-${filename}`);
    fs.writeFileSync(filepath, buffer);
    this.status.set(id, 'queued');
    // kick off processing (do not await)
    this.processDocument(id, filepath).catch((e) => this.logger.error(e));
    return { documentId: id, filepath };
  }

  async processDocument(documentId: string, filepath: string) {
    this.status.set(documentId, 'processing');
    let rawText = '';
    try {
      rawText = await OcrAdapter.performOcr(filepath);
      // basic NLP extraction heuristics
      const fields: FieldExtraction[] = [];
      // dates
      const dateRe = /\b(\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4})\b/g;
      const dates = Array.from(new Set((rawText.match(dateRe) || [])));
      dates.forEach((d) => fields.push({ field: 'date', value: d, confidence: 0.9 }));

      // amounts ($, EUR, numbers with commas)
      const amtRe = /\$\s?[0-9\,\.]+|€\s?[0-9\,\.]+|\b[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?\b/g;
      const amts = Array.from(new Set((rawText.match(amtRe) || [])));
      amts.forEach((a) => fields.push({ field: 'amount', value: a.trim(), confidence: 0.85 }));

      // names: heuristic capitalized pairs (First Last)
      const nameRe = /\b([A-Z][a-z]+\s+[A-Z][a-z]+)\b/g;
      const names = Array.from(new Set((rawText.match(nameRe) || []))).slice(0, 5);
      names.forEach((n) => fields.push({ field: 'name', value: n.trim(), confidence: 0.6 }));

      // clauses: capture headings like "Clause X" or "Section"
      const clauseRe = /\b(Clause|Section)\s+\d+[:\.\-]?\s*(.*?)\n/g;
      const clauseMatches = [] as string[];
      let m;
      while ((m = clauseRe.exec(rawText)) !== null) {
        clauseMatches.push(m[0].trim());
      }
      clauseMatches.slice(0, 10).forEach((c) =>
        fields.push({ field: 'clause', value: c, confidence: 0.7 }),
      );

      // signatures: look for 'Signed' or '/s/' markers
      const sigRe = /Signed\b|\/s\//g;
      if (sigRe.test(rawText)) {
        fields.push({ field: 'signature', value: 'present', confidence: 0.75 });
      }

      // confidence scoring per field is heuristic. In production replace with ML models.
      const result: ExtractionResultDto = {
        documentId,
        filename: path.basename(filepath),
        extractedAt: Date.now(),
        fields,
        rawText: rawText.slice(0, 20000),
        status: 'done',
      };

      this.results.set(documentId, result);
      this.status.set(documentId, 'done');

      // Persist to DB if Prisma is available
      try {
        if (this.prisma) {
          const doc = await this.prisma.document.create({
            data: {
              filename: path.basename(filepath),
              filepath,
              status: 'done',
              extractions: {
                create: fields.map((f) => ({ field: f.field, value: f.value, confidence: Number(f.confidence) })),
              },
            },
            include: { extractions: true },
          });
          // write audit log via DB
          await this.prisma.auditLog.create({ data: { documentId: doc.id, action: 'processed', metadata: { fieldCount: fields.length } } });
        } else {
          // write audit log to disk
          this.writeAudit(documentId, 'processed', { filepath, fieldCount: fields.length });
        }
      } catch (e) {
        this.logger.debug('Prisma persistence failed: ' + (e as Error).message);
        this.writeAudit(documentId, 'processed', { filepath, fieldCount: fields.length });
      }
    } catch (e) {
      this.status.set(documentId, 'failed');
      this.results.set(documentId, { documentId, filename: path.basename(filepath), extractedAt: Date.now(), fields: [], rawText: '', status: 'failed' });
      this.writeAudit(documentId, 'error', { error: (e as Error).message });
      throw e;
    }
  }

  getStatus(documentId: string) {
    return this.status.get(documentId) || 'not_found';
  }

  getResult(documentId: string) {
    return this.results.get(documentId) || null;
  }

  async writeAudit(documentId: string, action: string, metadata: any) {
    const ts = Date.now();
    try {
      const logDir = path.join(this.storeDir, 'audit');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      const file = path.join(logDir, `${documentId}-${ts}.json`);
      fs.writeFileSync(file, JSON.stringify({ documentId, action, metadata, ts }, null, 2));
    } catch (e) {
      this.logger.debug('Failed to write audit: ' + (e as Error).message);
    }
  }
}
