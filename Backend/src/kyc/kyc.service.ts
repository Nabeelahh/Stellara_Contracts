import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { OcrProvider } from './providers/ocr.provider';
import { DocumentType, OcrResult, FaceMatchResult, LivenessResult, VerificationStatus } from './types';

@Injectable()
export class KycService {
  private readonly logger = new Logger(KycService.name);

  constructor(
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Starts a new document verification session.
   */
  async startVerification(userId: string, docType: DocumentType) {
    const existingSession = await (this.prisma as any).verificationSession.findFirst({
      where: { userId, status: { in: ['PENDING', 'PROCESSING', 'MANUAL_REVIEW'] } },
    });

    if (existingSession) {
      throw new BadRequestException('Verification already in progress');
    }

    return (this.prisma as any).verificationSession.create({
      data: {
        userId,
        documentType: docType as any,
        status: 'PENDING',
      },
    });
  }

  /**
   * Processes the uploaded document and selfie.
   * This handles OCR, Face Match, and Liveness checks.
   */
  async processVerification(sessionId: string, documentUrl: string, selfieUrl: string) {
    const session = await (this.prisma as any).verificationSession.findUnique({
      where: { id: sessionId },
    });

    if (!session) throw new BadRequestException('Session not found');

    await (this.prisma as any).verificationSession.update({
      where: { id: sessionId },
      data: { status: 'PROCESSING', documentUrl, selfieUrl },
    });

    let status: VerificationStatus = VerificationStatus.VERIFIED;
    let failureReason: string | null = null;

    try {
      // 1. OCR Extraction (Mock for now, would use Textract in production)
      const ocrData = await this.mockOcr(documentUrl, session.documentType as any);

      // 1.1 Fraud Detection: Check for duplicate document numbers
      if (ocrData.documentNumber) {
        const duplicate = await (this.prisma as any).verificationSession.findFirst({
          where: {
            id: { not: sessionId },
            status: 'VERIFIED',
            // Note: In Prisma with JSON fields, we usually use jsonPath or similar filtering
            // For this mock/architecture implementation, we assume a structured check
          },
        });
        
        // Simulating the check logic
        if (duplicate && (duplicate.ocrData as any)?.documentNumber === ocrData.documentNumber) {
          status = VerificationStatus.REJECTED;
          failureReason = 'Document already registered to another account';
          await (this.prisma as any).verificationSession.update({
            where: { id: sessionId },
            data: { status: status as any, failureReason },
          });
          return { status, failureReason };
        }
      }
      
      // 2. Face Match (Mock for now, would use Rekognition in production)
      const faceMatch = await this.mockFaceMatch(documentUrl, selfieUrl);

      // 3. Liveness Check (Mock for now)
      const liveness = await this.mockLiveness(selfieUrl);

      // 4. Decision Logic
      if (faceMatch.score < 95) {
        status = VerificationStatus.REJECTED;
        failureReason = 'Face match score too low';
      } else if (!liveness.passed) {
        status = VerificationStatus.REJECTED;
        failureReason = 'Liveness check failed';
      } else if (ocrData.confidence < 0.8) {
        status = VerificationStatus.MANUAL_REVIEW;
        failureReason = 'Low OCR confidence';
      }

      await (this.prisma as any).verificationSession.update({
        where: { id: sessionId },
        data: {
          status: status as any,
          ocrData: ocrData as any,
          faceMatchScore: faceMatch.score,
          livenessScore: liveness.score,
          failureReason,
        },
      });

      return { status, failureReason };

    } catch (error) {
      this.logger.error(`Error processing verification for session ${sessionId}`, error);
      await (this.prisma as any).verificationSession.update({
        where: { id: sessionId },
        data: { status: 'REJECTED', failureReason: 'Internal processing error' },
      });
      throw error;
    }
  }

  /**
   * Manual review for edge cases.
   */
  async reviewVerification(sessionId: string, moderatorId: string, approved: boolean, note?: string) {
    return (this.prisma as any).verificationSession.update({
      where: { id: sessionId },
      data: {
        status: approved ? 'VERIFIED' : 'REJECTED',
        manualReviewBy: moderatorId,
        manualReviewAt: new Date(),
        manualNote: note,
      },
    });
  }

  // --- Mock implementation for demonstration ---

  private async mockOcr(url: string, type: DocumentType): Promise<OcrResult> {
    this.logger.log(`Mock OCR extraction for ${url} as ${type}`);
    return {
      firstName: 'John',
      lastName: 'Doe',
      dateOfBirth: '1990-01-01',
      documentNumber: 'A123456789',
      confidence: 0.95,
      rawText: 'PASSPORT... JOHN DOE... 1990-01-01...',
    };
  }

  private async mockFaceMatch(idUrl: string, selfUrl: string): Promise<FaceMatchResult> {
    this.logger.log(`Mock Face Match between ${idUrl} and ${selfUrl}`);
    return { score: 98, isMatch: true };
  }

  private async mockLiveness(url: string): Promise<LivenessResult> {
    this.logger.log(`Mock Liveness check for ${url}`);
    return { score: 0.99, passed: true };
  }
}
