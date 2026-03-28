import { OcrResult, DocumentType } from '../types';

export interface OcrProvider {
  /**
   * Extract text data from a document image
   */
  extract(imageUrl: string, docType: DocumentType): Promise<OcrResult>;

  /**
   * Verify security features like MRZ, and consistency
   */
  verifyAuthenticity(ocrData: OcrResult): Promise<{
    isValid: boolean;
    flags: string[];
    confidence: number;
  }>;
}
