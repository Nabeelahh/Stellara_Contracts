import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PricesGateway } from './gateways/prices.gateway';
import { TradesGateway } from './gateways/trades.gateway';
import { MessagesGateway } from './gateways/messages.gateway';
import { WebsocketService } from './websocket.service';
import { ConnectionStateService } from './connection-state.service';
import { WsJwtGuard } from './ws-jwt.guard';
import { AuthModule } from '../auth/auth.module';
import { SessionModule } from '../sessions/session.module';

import { WebsocketLoadBalancerService } from './load-balancer.service';

@Module({
  imports: [
    AuthModule,
    SessionModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET', 'super_secret_key_for_development'),
      }),
    }),
  ],
  providers: [
    PricesGateway,
    TradesGateway,
    MessagesGateway,
    WebsocketService,
    ConnectionStateService,
    WebsocketLoadBalancerService,
    WsJwtGuard,
  ],
  exports: [WebsocketService, WebsocketLoadBalancerService],
})
export class WebsocketModule {}
