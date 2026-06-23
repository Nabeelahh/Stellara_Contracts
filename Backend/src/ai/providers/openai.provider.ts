import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { AiProvider } from '../ai.provider';

interface CircuitBreakerState {
  failures: number;
  openedAt: number | null;
  state: 'closed' | 'open' | 'half-open';
}

@Injectable()
export class OpenAiProvider implements AiProvider, OnModuleInit {
  private readonly logger = new Logger(OpenAiProvider.name);
  private readonly apiKey: string;
  private readonly timeoutMs: number;
  private readonly cb: CircuitBreakerState = {
    failures: 0,
    openedAt: null,
    state: 'closed',
  };
  private readonly FAILURE_THRESHOLD = 5;
  private readonly HALF_OPEN_AFTER_MS = 60_000;

  constructor(private readonly config: ConfigService) {
    this.apiKey = this.config.get<string>('OPENAI_API_KEY') ?? '';
    this.timeoutMs = this.config.get<number>('AI_TIMEOUT_MS') ?? 30_000;
  }

  onModuleInit(): void {
    if (!this.apiKey) {
      throw new Error(
        'OPENAI_API_KEY is not set. AI features require a valid API key at startup.',
      );
    }
  }

  async generate(
    prompt: string,
  ): Promise<{ response: string; tokensUsed: number }> {
    this.checkCircuit();

    try {
      const res = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        {
          model: this.config.get<string>('OPENAI_MODEL') ?? 'gpt-4',
          messages: [{ role: 'user', content: prompt }],
        },
        {
          headers: { Authorization: `Bearer ${this.apiKey}` },
          timeout: this.timeoutMs,
        },
      );

      this.recordSuccess();

      return {
        response: res.data.choices[0].message.content as string,
        tokensUsed: res.data.usage?.total_tokens ?? 0,
      };
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }

  private checkCircuit(): void {
    const { state, openedAt } = this.cb;
    if (state === 'open') {
      const elapsed = Date.now() - (openedAt ?? 0);
      if (elapsed >= this.HALF_OPEN_AFTER_MS) {
        this.cb.state = 'half-open';
        this.logger.warn('Circuit half-open: allowing probe request');
      } else {
        throw new Error('Circuit breaker is open');
      }
    }
  }

  private recordSuccess(): void {
    this.cb.failures = 0;
    this.cb.state = 'closed';
    this.cb.openedAt = null;
  }

  private recordFailure(): void {
    this.cb.failures += 1;
    this.logger.warn(`AI provider failure #${this.cb.failures}`);
    if (this.cb.failures >= this.FAILURE_THRESHOLD) {
      this.cb.state = 'open';
      this.cb.openedAt = Date.now();
      this.logger.error('Circuit breaker opened');
    }
  }

  getCircuitState(): CircuitBreakerState['state'] {
    return this.cb.state;
  }
}
