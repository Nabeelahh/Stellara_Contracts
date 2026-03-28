export interface FieldExtraction {
  field: string;
  value: string;
  confidence: number; // 0..1
}

export interface ExtractionResultDto {
  documentId: string;
  filename: string;
  extractedAt: number;
  fields: FieldExtraction[];
  rawText?: string;
  status: 'done' | 'failed';
}
