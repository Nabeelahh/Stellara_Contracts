import { Injectable, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool, PoolConfig } from 'pg';

@Injectable()
export class PostgresService implements OnApplicationShutdown {
  private readonly pool: Pool;

  constructor(private readonly configService: ConfigService) {
    const connectionString = this.configService.get<string>('DATABASE_URL');

    const config: PoolConfig = connectionString
      ? { connectionString }
      : {
          host: this.configService.get<string>('DATABASE_HOST', 'localhost'),
          port: parseInt(this.configService.get<string>('DATABASE_PORT', '5432'), 10),
          user: this.configService.get<string>('DATABASE_USER', 'postgres'),
          password: this.configService.get<string>('DATABASE_PASSWORD', 'postgres'),
          database: this.configService.get<string>('DATABASE_NAME', 'app_db'),
        };

    this.pool = new Pool(config);
  }

  async query<T = any>(text: string, values: any[] = []): Promise<T[]> {
    const result = await this.pool.query(text, values);
    return result.rows as T[];
  }

  async execute(text: string, values: any[] = []): Promise<void> {
    await this.pool.query(text, values);
  }

  async healthCheck(): Promise<void> {
    await this.pool.query('SELECT 1');
  }

  async onApplicationShutdown(): Promise<void> {
    await this.pool.end();
  }
}
