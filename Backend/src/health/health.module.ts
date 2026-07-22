import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bull';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { StellarMonitorModule } from '../stellar-monitor/stellar-monitor.module';
import { HealthController } from './health.controller';
import { DatabaseHealthIndicator } from './database-health.indicator';
import { RedisHealthIndicator } from './redis-health.indicator';
import { QueueHealthIndicator } from './queue-health.indicator';
import { AuthHealthIndicator } from './auth-health.indicator';

@Module({
  imports: [
    StellarMonitorModule,
    TypeOrmModule.forFeature([]),
    BullModule.registerQueue(
      { name: 'deploy-contract' },
      { name: 'process-tts' },
      { name: 'index-market-news' },
    ),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
    ConfigModule,
  ],
  controllers: [HealthController],
  providers: [
    DatabaseHealthIndicator,
    RedisHealthIndicator,
    QueueHealthIndicator,
    AuthHealthIndicator,
  ],
})
export class HealthModule {}
