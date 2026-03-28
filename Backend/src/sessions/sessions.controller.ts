import { Controller, Delete, Get, Param, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SessionService } from './session.service';

@Controller('sessions')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private readonly sessionService: SessionService) {}

  @Get()
  async getActiveSessions(@CurrentUser() user: any) {
    return this.sessionService.listSessions(user.id, user.sessionId);
  }

  @Get('alerts')
  async getSecurityAlerts(@CurrentUser() user: any) {
    return this.sessionService.getSecurityAlerts(user.id);
  }

  @Delete('others')
  async terminateOtherSessions(@CurrentUser() user: any) {
    const terminatedCount = await this.sessionService.terminateOtherSessions(
      user.id,
      user.sessionId,
    );

    return { terminatedCount };
  }

  @Delete(':id')
  async terminateSession(@CurrentUser() user: any, @Param('id') sessionId: string) {
    await this.sessionService.terminateSession(user.id, sessionId);
    return { sessionId, terminated: true };
  }

  @Get(':id/activity')
  async getSessionActivity(
    @CurrentUser() user: any,
    @Param('id') sessionId: string,
    @Req() req: Request,
  ) {
    const sessions = await this.sessionService.listSessions(user.id, req.user?.sessionId);
    const session = sessions.find((entry) => entry.sessionId === sessionId);

    if (!session) {
      return [];
    }

    return this.sessionService.getSessionActivity(sessionId);
  }
}
