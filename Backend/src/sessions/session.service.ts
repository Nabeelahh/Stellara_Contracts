import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { randomUUID, createHash } from 'node:crypto';
import { UAParser } from 'ua-parser-js';
import * as bcrypt from 'bcrypt';
import { distributedlock } from '../redis/distributed-lock.decorator';
import { RedisService } from '../redis/redis.service';
import { parseDurationToSeconds } from '../common/utils/duration.util';

export interface SessionRecord {
  sessionId: string;
  userId: string;
  walletAddress: string;
  roles: string[];
  subscriptionTier: string;
  createdAt: string;
  lastActivityAt: string;
  lastRefreshAt: string;
  expiresAt: string;
  refreshTokenHash: string;
  suspicious: boolean;
  suspiciousReasons: string[];
  device: {
    browser: string;
    os: string;
    deviceType: string;
    ip: string;
    location: string;
    fingerprint: string;
    userAgent: string;
  };
}

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);
  private readonly sessionTtlSeconds = parseDurationToSeconds(
    process.env.SESSION_TTL_SECONDS || process.env.JWT_REFRESH_EXPIRATION,
    7 * 24 * 60 * 60,
  );

  constructor(private readonly redisService: RedisService) {}

  createSessionId(): string {
    return randomUUID();
  }

  @distributedlock({ key: 'user:{id}' })
  async createSession(
    user: {
      id: string;
      walletAddress: string;
      roles: string[];
      subscriptionTier?: string;
    },
    sessionId: string,
    refreshToken: string,
    request: Request,
  ): Promise<SessionRecord> {
    const now = new Date();
    const existingSessions = await this.listSessions(user.id);
    const device = this.extractDeviceInfo(request);
    const suspiciousReasons = this.detectSuspiciousActivity(existingSessions, device);

    const session: SessionRecord = {
      sessionId,
      userId: user.id,
      walletAddress: user.walletAddress,
      roles: user.roles || [],
      subscriptionTier: user.subscriptionTier || 'free',
      createdAt: now.toISOString(),
      lastActivityAt: now.toISOString(),
      lastRefreshAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.sessionTtlSeconds * 1000).toISOString(),
      refreshTokenHash: await bcrypt.hash(refreshToken, 10),
      suspicious: suspiciousReasons.length > 0,
      suspiciousReasons,
      device,
    };

    await this.persistSession(session);
    await this.logActivity(sessionId, 'session_created', {
      suspicious: session.suspicious,
      suspiciousReasons,
      device,
    });

    if (session.suspicious) {
      await this.logSecurityAlert(session);
    }

    return session;
  }

  @distributedlock({ key: 'user:{id}' })
  async validateRefreshSession(
    userId: string,
    sessionId: string,
    refreshToken: string,
  ): Promise<SessionRecord> {
    const session = await this.getRequiredSession(userId, sessionId);
    const tokenMatches = await bcrypt.compare(refreshToken, session.refreshTokenHash);

    if (!tokenMatches) {
      await this.logActivity(sessionId, 'invalid_refresh_token', {
        userId,
      });
      throw new UnauthorizedException('Refresh session is invalid');
    }

    return session;
  }

  @distributedlock({ key: 'user:{id}' })
  async rotateRefreshToken(
    userId: string,
    sessionId: string,
    refreshToken: string,
    request: Request,
  ): Promise<SessionRecord> {
    const session = await this.getRequiredSession(userId, sessionId);
    const now = new Date().toISOString();

    session.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    session.lastRefreshAt = now;
    session.lastActivityAt = now;
    session.expiresAt = new Date(Date.now() + this.sessionTtlSeconds * 1000).toISOString();
    session.device = this.extractDeviceInfo(request);

    await this.persistSession(session);
    await this.logActivity(sessionId, 'refresh_rotated', {
      userId,
      ip: session.device.ip,
    });

    return session;
  }

  async validateAccessSession(
    userId: string,
    sessionId: string,
    request?: Request,
  ): Promise<SessionRecord> {
    const session = await this.getRequiredSession(userId, sessionId);
    const now = new Date();
    const lastSeen = new Date(session.lastActivityAt);

    if (now.getTime() - lastSeen.getTime() >= 60_000) {
      session.lastActivityAt = now.toISOString();
      if (request) {
        session.device = this.extractDeviceInfo(request);
      }
      await this.persistSession(session);
    }

    return session;
  }

  async listSessions(
    userId: string,
    currentSessionId?: string,
  ): Promise<Array<SessionRecord & { current: boolean }>> {
    const redis = this.redisService.getClient();
    const sessionIds = await redis.zrevrange(this.userSessionsKey(userId), 0, -1);
    const sessions: Array<SessionRecord & { current: boolean }> = [];

    for (const sessionId of sessionIds) {
      const session = await this.getSession(sessionId);
      if (!session) {
        await redis.zrem(this.userSessionsKey(userId), sessionId);
        continue;
      }

      sessions.push({
        ...session,
        current: session.sessionId === currentSessionId,
      });
    }

    return sessions;
  }

  @distributedlock({ key: 'user:{id}' })
  async terminateSession(
    userId: string,
    sessionId: string,
    reason = 'terminated_by_user',
  ): Promise<void> {
    const session = await this.getRequiredSession(userId, sessionId);
    await this.deleteSession(session.userId, session.sessionId);
    await this.logActivity(sessionId, 'session_terminated', { reason });
  }

  @distributedlock({ key: 'user:{id}' })
  async terminateOtherSessions(userId: string, currentSessionId: string): Promise<number> {
    const sessions = await this.listSessions(userId, currentSessionId);
    const otherSessions = sessions.filter((session) => !session.current);

    await Promise.all(
      otherSessions.map((session) => this.deleteSession(userId, session.sessionId)),
    );

    await this.logActivity(currentSessionId, 'other_sessions_terminated', {
      total: otherSessions.length,
    });

    return otherSessions.length;
  }

  async getSessionActivity(sessionId: string): Promise<any[]> {
    const entries = await this.redisService
      .getClient()
      .lrange(this.sessionActivityKey(sessionId), 0, 49);

    return entries.map((entry) => JSON.parse(entry));
  }

  async getSecurityAlerts(userId: string): Promise<any[]> {
    const entries = await this.redisService
      .getClient()
      .lrange(this.securityAlertsKey(userId), 0, 49);

    return entries.map((entry) => JSON.parse(entry));
  }

  private async getRequiredSession(userId: string, sessionId: string): Promise<SessionRecord> {
    const session = await this.getSession(sessionId);

    if (!session || session.userId !== userId) {
      throw new UnauthorizedException('Session is not active');
    }

    return session;
  }

  private async getSession(sessionId: string): Promise<SessionRecord | null> {
    const payload = await this.redisService.getClient().get(this.sessionKey(sessionId));

    if (!payload) {
      return null;
    }

    return JSON.parse(payload) as SessionRecord;
  }

  private async persistSession(session: SessionRecord): Promise<void> {
    const redis = this.redisService.getClient();
    const timestampScore = new Date(session.lastActivityAt).getTime();

    await redis.set(
      this.sessionKey(session.sessionId),
      JSON.stringify(session),
      'EX',
      this.sessionTtlSeconds,
    );
    await redis.zadd(this.userSessionsKey(session.userId), timestampScore, session.sessionId);
    await redis.expire(this.userSessionsKey(session.userId), this.sessionTtlSeconds);
  }

  private async deleteSession(userId: string, sessionId: string): Promise<void> {
    const redis = this.redisService.getClient();
    await redis.del(this.sessionKey(sessionId));
    await redis.zrem(this.userSessionsKey(userId), sessionId);
  }

  private extractDeviceInfo(request: Request) {
    const userAgent = request.headers['user-agent'] || 'unknown';
    const parser = new UAParser(userAgent);
    const browser = parser.getBrowser();
    const os = parser.getOS();
    const device = parser.getDevice();
    const forwardedFor = String(request.headers['x-forwarded-for'] || '')
      .split(',')[0]
      .trim();
    const ip = forwardedFor || request.ip || 'unknown';
    const location = this.buildLocationFromHeaders(request);
    const fingerprint = createHash('sha256')
      .update(
        [
          userAgent,
          request.headers['accept-language'] || '',
          request.headers['sec-ch-ua-platform'] || '',
          request.headers['sec-ch-ua'] || '',
        ].join('|'),
      )
      .digest('hex');

    return {
      browser: [browser.name, browser.version].filter(Boolean).join(' ') || 'unknown',
      os: [os.name, os.version].filter(Boolean).join(' ') || 'unknown',
      deviceType: device.type || 'desktop',
      ip,
      location,
      fingerprint,
      userAgent,
    };
  }

  private buildLocationFromHeaders(request: Request): string {
    const country =
      request.headers['cf-ipcountry'] ||
      request.headers['x-vercel-ip-country'] ||
      request.headers['x-country-code'] ||
      request.headers['x-country'];
    const region = request.headers['x-vercel-ip-country-region'] || request.headers['x-region'];
    const city = request.headers['x-vercel-ip-city'] || request.headers['x-city'];

    return (
      [country, region, city]
        .filter(Boolean)
        .map((part) => String(part))
        .join(', ') || 'unknown'
    );
  }

  private detectSuspiciousActivity(
    existingSessions: Array<SessionRecord & { current?: boolean }>,
    device: SessionRecord['device'],
  ): string[] {
    const reasons: string[] = [];

    if (
      existingSessions.some(
        (session) =>
          session.device.location !== 'unknown' && session.device.location !== device.location,
      )
    ) {
      reasons.push('new_location_detected');
    }

    if (existingSessions.some((session) => session.device.fingerprint !== device.fingerprint)) {
      reasons.push('new_device_fingerprint');
    }

    const uniqueIps = new Set(existingSessions.map((session) => session.device.ip));
    uniqueIps.add(device.ip);
    if (uniqueIps.size >= 4) {
      reasons.push('multiple_ips_detected');
    }

    return reasons;
  }

  private async logSecurityAlert(session: SessionRecord): Promise<void> {
    const alert = {
      type: 'suspicious_session_activity',
      sessionId: session.sessionId,
      reasons: session.suspiciousReasons,
      device: session.device,
      timestamp: new Date().toISOString(),
    };

    this.logger.warn(
      `Suspicious session activity for user ${session.userId}: ${session.suspiciousReasons.join(', ')}`,
    );

    await this.redisService
      .getClient()
      .lpush(this.securityAlertsKey(session.userId), JSON.stringify(alert));
    await this.redisService.getClient().ltrim(this.securityAlertsKey(session.userId), 0, 49);
    await this.redisService
      .getClient()
      .expire(this.securityAlertsKey(session.userId), this.sessionTtlSeconds);
  }

  private async logActivity(
    sessionId: string,
    event: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    const redis = this.redisService.getClient();
    const entry = JSON.stringify({
      event,
      metadata,
      timestamp: new Date().toISOString(),
    });

    await redis.lpush(this.sessionActivityKey(sessionId), entry);
    await redis.ltrim(this.sessionActivityKey(sessionId), 0, 99);
    await redis.expire(this.sessionActivityKey(sessionId), this.sessionTtlSeconds);
  }

  private sessionKey(sessionId: string): string {
    return `session:${sessionId}`;
  }

  private userSessionsKey(userId: string): string {
    return `user-sessions:${userId}`;
  }

  private sessionActivityKey(sessionId: string): string {
    return `session-activity:${sessionId}`;
  }

  private securityAlertsKey(userId: string): string {
    return `security-alerts:${userId}`;
  }
}
