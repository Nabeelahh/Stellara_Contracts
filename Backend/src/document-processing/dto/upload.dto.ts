export class UploadResultDto {
  documentId: string;
  filename: string;
  status: 'queued' | 'processing' | 'done' | 'failed';
}
