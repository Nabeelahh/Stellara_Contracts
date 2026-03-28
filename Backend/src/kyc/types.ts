export enum VerificationStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
  MANUAL_REVIEW = 'MANUAL_REVIEW',
}

export enum DocumentType {
  PASSPORT = 'PASSPORT',
  DRIVERS_LICENSE = 'DRIVERS_LICENSE',
  NATIONAL_ID = 'NATIONAL_ID',
}

export interface OcrResult {
  firstName?: string;
  lastName?: string;
  dateOfBirth?: string;
  documentNumber?: string;
  expiryDate?: string;
  issuingCountry?: string;
  mrz?: string;
  confidence: number;
  rawText: string;
}

export interface FaceMatchResult {
  score: number;
  isMatch: boolean;
}

export interface LivenessResult {
  score: number;
  passed: boolean;
}
