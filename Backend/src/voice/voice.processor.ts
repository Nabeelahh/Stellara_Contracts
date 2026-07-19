// src/voice/voice.processor.ts
import { Process, Processor } from '@nestjs/bull';
import type { Job } from 'bull';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { VoiceJob, JobStatus } from './entities/voice-job.entity';
import { VoiceService } from './services/voice.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { QueueJobTracingWrapper } from '../observability/middleware/queue-job-tracing.wrapper';
import { MetricsService } from '../observability/services/metrics.service';

@Processor('voice-processing')
export class VoiceProcessor {
  constructor(
    @InjectRepository(VoiceJob)
    private voiceJobRepository: Repository<VoiceJob>,
    private voiceService: VoiceService,
    private readonly queueJobTracingWrapper: QueueJobTracingWrapper,
    private readonly metricsService: MetricsService,
  ) {}

  @Process('process-stt')
  async handleSTT(job: Job) {
    const wrappedProcess = this.queueJobTracingWrapper.wrapProcessor(
      async (jobToProcess: Job) => {
        const { jobId } = jobToProcess.data;
        const start = Date.now();

        this.metricsService.recordJobStart('voice-processing');

        try {
          const voiceJob = await this.voiceJobRepository.findOne({
            where: { id: jobId },
          });
          if (!voiceJob) throw new Error('Job not found');

          await this.voiceService.updateJobStatus(jobId, JobStatus.PROCESSING);

          // Simulate Whisper API call
          const transcribedText = await this.transcribeAudio(voiceJob.audioUrl);

          await this.voiceService.updateJobStatus(jobId, JobStatus.COMPLETED, {
            transcribedText,
          });

          const duration = (Date.now() - start) / 1000;
          this.metricsService.recordJobCompleted('voice-processing', duration);
        } catch (error: any) {
          const duration = (Date.now() - start) / 1000;
          this.metricsService.recordJobFailed('voice-processing', duration, error.constructor.name);
          const canRetry = await this.voiceService.incrementRetry(jobId);

          if (canRetry) {
            await this.voiceService.updateJobStatus(jobId, JobStatus.PENDING);
            throw error; // Bull will retry
          } else {
            await this.voiceService.updateJobStatus(jobId, JobStatus.FAILED, {
              errorMessage: error.message,
            });
          }
        }
      },
      'voice-processing',
    );

    return wrappedProcess(job);
  }

  @Process('process-tts')
  async handleTTS(job: Job) {
    const wrappedProcess = this.queueJobTracingWrapper.wrapProcessor(
      async (jobToProcess: Job) => {
        const { jobId } = jobToProcess.data;
        const start = Date.now();

        this.metricsService.recordJobStart('voice-processing');

        try {
          const voiceJob = await this.voiceJobRepository.findOne({
            where: { id: jobId },
          });
          if (!voiceJob) throw new Error('Job not found');

          await this.voiceService.updateJobStatus(jobId, JobStatus.PROCESSING);

          // Simulate TTS API call
          const audioPath = await this.generateSpeech(voiceJob.inputText || '');

          await this.voiceService.updateJobStatus(jobId, JobStatus.COMPLETED, {
            generatedAudioUrl: audioPath,
          });

          const duration = (Date.now() - start) / 1000;
          this.metricsService.recordJobCompleted('voice-processing', duration);
        } catch (error: any) {
          const duration = (Date.now() - start) / 1000;
          this.metricsService.recordJobFailed('voice-processing', duration, error.constructor.name);
          const canRetry = await this.voiceService.incrementRetry(jobId);

          if (canRetry) {
            await this.voiceService.updateJobStatus(jobId, JobStatus.PENDING);
            throw error; // Bull will retry
          } else {
            await this.voiceService.updateJobStatus(jobId, JobStatus.FAILED, {
              errorMessage: error.message,
            });
          }
        }
      },
      'voice-processing',
    );

    return wrappedProcess(job);
  }

  private async transcribeAudio(audioPath: string | null): Promise<string> {
    // TODO: Integrate with OpenAI Whisper API
    // For now, return mock data
    await new Promise((resolve) => setTimeout(resolve, 2000));
    return 'Transcribed text from audio';
  }

  private async generateSpeech(text: string): Promise<string> {
    // TODO: Integrate with TTS API (OpenAI TTS, Google Cloud TTS, etc.)
    const outputDir = path.join(process.cwd(), 'uploads', 'tts');
    await fs.mkdir(outputDir, { recursive: true });
    const fileName = `${Date.now()}-speech.mp3`;
    const filePath = path.join(outputDir, fileName);

    // Mock: create empty file
    await fs.writeFile(filePath, Buffer.from(''));

    return filePath;
  }
}
