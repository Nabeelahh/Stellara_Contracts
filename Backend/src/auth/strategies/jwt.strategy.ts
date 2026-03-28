import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { SessionService } from '../../sessions/session.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
    private readonly sessionService: SessionService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          let token = null;
          if (request && request.cookies) {
            token = request.cookies['access_token'];
          }
          if (!token && request.headers.authorization) {
            token = request.headers.authorization.split(' ')[1];
          }
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET', 'super_secret_key_for_development'),
      passReqToCallback: true,
    });
  }

  async validate(request: Request, payload: any) {
    let token = request.cookies?.['access_token'];
    if (!token && request.headers.authorization) {
      token = request.headers.authorization.split(' ')[1];
    }

    if (token) {
      const isBlacklisted = await this.authService.isTokenBlacklisted(token);
      if (isBlacklisted) {
        throw new UnauthorizedException('Token is blacklisted');
      }
    }

    if (payload.sid) {
      await this.sessionService.validateAccessSession(payload.sub, payload.sid, request);
    }

    return {
      id: payload.sub,
      walletAddress: payload.walletAddress,
      roles: payload.roles,
      sessionId: payload.sid,
      subscriptionTier: payload.subscriptionTier,
    };
  }
}
