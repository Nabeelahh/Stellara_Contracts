import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { WsException } from '@nestjs/websockets';
import { Socket } from 'socket.io';
import { AuthService } from '../auth/auth.service';
import { SessionService } from '../sessions/session.service';

@Injectable()
export class WsJwtGuard implements CanActivate {
  private readonly logger = new Logger(WsJwtGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly sessionService: SessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient();
    const token = this.extractToken(client);

    if (!token) {
      throw new WsException('Missing authentication token');
    }

    try {
      const secret = this.configService.get<string>(
        'JWT_SECRET',
        'super_secret_key_for_development',
      );
      const payload = this.jwtService.verify(token, { secret });

      const isBlacklisted = await this.authService.isTokenBlacklisted(token);
      if (isBlacklisted) {
        throw new WsException('Token is blacklisted');
      }

      if (payload.sid) {
        await this.sessionService.validateAccessSession(payload.sub, payload.sid);
      }

      // Attach user to socket data
      client.data.user = {
        id: payload.sub,
        walletAddress: payload.walletAddress,
        roles: payload.roles,
        sessionId: payload.sid,
        subscriptionTier: payload.subscriptionTier,
      };

      return true;
    } catch (err) {
      this.logger.warn(`WS auth failed: ${err.message}`);
      throw new WsException('Unauthorized');
    }
  }

  private extractToken(client: Socket): string | null {
    // Try Authorization header first
    const authHeader = client.handshake.headers?.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.split(' ')[1];
    }
    // Fall back to query param or auth object
    return (
      (client.handshake.auth?.token as string) || (client.handshake.query?.token as string) || null
    );
  }
}
