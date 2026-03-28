import { 
  Controller, 
  Get, 
  Post, 
  Put, 
  Delete, 
  Body, 
  Param, 
  Query, 
  UseGuards, 
  Request,
  HttpStatus,
  HttpCode
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { SupportService } from './support.service';
import { ZendeskService } from './zendesk.service';
import { SupportGuard } from './guards/support.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Role } from '@prisma/client';
import * as dto from './dto';

@ApiTags('Support Tools')
@ApiBearerAuth()
@UseGuards(SupportGuard)
@Controller('support')
export class SupportController {
  constructor(
    private readonly supportService: SupportService,
    private readonly zendeskService: ZendeskService
  ) {}

  // ─── User Lookup & Unified View ───────────────────────────────────────────────

  @Get('users/lookup')
  @ApiOperation({ summary: 'Find user by various criteria' })
  @ApiResponse({ status: 200, description: 'User found' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async findUser(@Query() query: dto.UserLookupDto) {
    return this.supportService.findUser(query);
  }

  @Get('users/:userId/timeline')
  @ApiOperation({ summary: 'Get user activity timeline' })
  @ApiResponse({ status: 200, description: 'Activity timeline retrieved' })
  async getActivityTimeline(
    @Param('userId') userId: string,
    @Query() query: dto.ActivityTimelineDto
  ) {
    return this.supportService.getActivityTimeline(userId, query);
  }

  // ─── Support Notes ───────────────────────────────────────────────────────────

  @Post('notes')
  @ApiOperation({ summary: 'Create support note' })
  @ApiResponse({ status: 201, description: 'Note created' })
  async createNote(@Body() dto: dto.CreateSupportNoteDto, @Request() req) {
    return this.supportService.createSupportNote(dto, req.user.id);
  }

  @Put('notes/:id')
  @ApiOperation({ summary: 'Update support note' })
  @ApiResponse({ status: 200, description: 'Note updated' })
  async updateNote(
    @Param('id') id: string,
    @Body() dto: dto.UpdateSupportNoteDto,
    @Request() req
  ) {
    return this.supportService.updateSupportNote(id, dto, req.user.id);
  }

  @Delete('notes/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete support note' })
  @ApiResponse({ status: 204, description: 'Note deleted' })
  async deleteNote(@Param('id') id: string, @Request() req) {
    return this.supportService.deleteSupportNote(id, req.user.id);
  }

  @Get('users/:userId/notes')
  @ApiOperation({ summary: 'Get user support notes' })
  @ApiResponse({ status: 200, description: 'Notes retrieved' })
  async getUserNotes(
    @Param('userId') userId: string,
    @Query('includeInternal') includeInternal?: string
  ) {
    return this.supportService.getSupportNotes(userId, includeInternal === 'true');
  }

  // ─── Manual Adjustments ───────────────────────────────────────────────────────

  @Post('adjustments')
  @Roles(Role.SUPPORT_AGENT, Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Create manual adjustment' })
  @ApiResponse({ status: 201, description: 'Adjustment created' })
  async createAdjustment(@Body() dto: dto.CreateManualAdjustmentDto, @Request() req) {
    return this.supportService.createManualAdjustment(dto, req.user.id);
  }

  @Put('adjustments/approve')
  @Roles(Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Approve manual adjustment' })
  @ApiResponse({ status: 200, description: 'Adjustment approved' })
  async approveAdjustment(@Body() dto: dto.ApproveAdjustmentDto, @Request() req) {
    return this.supportService.approveAdjustment(dto, req.user.id);
  }

  @Put('adjustments/reject')
  @Roles(Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Reject manual adjustment' })
  @ApiResponse({ status: 200, description: 'Adjustment rejected' })
  async rejectAdjustment(@Body() dto: dto.RejectAdjustmentDto, @Request() req) {
    return this.supportService.rejectAdjustment(dto, req.user.id);
  }

  @Get('adjustments/pending')
  @Roles(Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Get pending adjustments' })
  @ApiResponse({ status: 200, description: 'Pending adjustments retrieved' })
  async getPendingAdjustments() {
    return this.supportService.getPendingAdjustments();
  }

  // ─── Support Actions & Impersonation ───────────────────────────────────────────

  @Post('actions')
  @ApiOperation({ summary: 'Create support action' })
  @ApiResponse({ status: 201, description: 'Action created' })
  async createAction(@Body() dto: dto.CreateSupportActionDto, @Request() req) {
    return this.supportService.createSupportAction(
      dto, 
      req.user.id, 
      req.ip, 
      req.headers['user-agent']
    );
  }

  @Post('impersonate/start')
  @Roles(Role.SUPPORT_AGENT, Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Start user impersonation' })
  @ApiResponse({ status: 201, description: 'Impersonation started' })
  async startImpersonation(@Body() dto: dto.ImpersonateUserDto, @Request() req) {
    return this.supportService.startImpersonation(
      dto, 
      req.user.id, 
      req.ip, 
      req.headers['user-agent']
    );
  }

  @Post('impersonate/end/:userId')
  @Roles(Role.SUPPORT_AGENT, Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'End user impersonation' })
  @ApiResponse({ status: 201, description: 'Impersonation ended' })
  async endImpersonation(
    @Param('userId') userId: string,
    @Request() req
  ) {
    return this.supportService.endImpersonation(
      userId, 
      req.user.id, 
      req.ip, 
      req.headers['user-agent']
    );
  }

  @Get('users/:userId/actions')
  @ApiOperation({ summary: 'Get user support actions' })
  @ApiResponse({ status: 200, description: 'Actions retrieved' })
  async getUserActions(@Param('userId') userId: string) {
    return this.supportService.getUserSupportActions(userId);
  }

  // ─── Zendesk Integration ───────────────────────────────────────────────────────

  @Get('zendesk/tickets/:userId')
  @ApiOperation({ summary: 'Get user Zendesk tickets' })
  @ApiResponse({ status: 200, description: 'Tickets retrieved' })
  async getUserTickets(@Param('userId') userId: string) {
    return this.zendeskService.getTicketsForUser(userId);
  }

  @Post('zendesk/sync/:ticketId')
  @ApiOperation({ summary: 'Sync Zendesk ticket' })
  @ApiResponse({ status: 200, description: 'Ticket synced' })
  async syncTicket(@Param('ticketId') ticketId: number) {
    return this.zendeskService.syncTicket(ticketId);
  }

  @Post('zendesk/link')
  @ApiOperation({ summary: 'Link user to Zendesk ticket' })
  @ApiResponse({ status: 201, description: 'Ticket linked' })
  async linkZendeskTicket(@Body() body: { userId: string; ticketId: number }) {
    return this.zendeskService.createZendeskLink(body.userId, body.ticketId);
  }

  @Put('zendesk/tickets/:ticketId/status')
  @Roles(Role.SUPPORT_AGENT, Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Update Zendesk ticket status' })
  @ApiResponse({ status: 200, description: 'Ticket status updated' })
  async updateTicketStatus(
    @Param('ticketId') ticketId: number,
    @Body() body: { status: string }
  ) {
    return this.zendeskService.updateTicketStatus(ticketId, body.status as any);
  }

  @Get('zendesk/tickets')
  @Roles(Role.SUPPORT_MANAGER, Role.SUPER_ADMIN)
  @ApiOperation({ summary: 'Get recent Zendesk tickets' })
  @ApiResponse({ status: 200, description: 'Tickets retrieved' })
  async getRecentTickets(@Query('limit') limit?: string) {
    return this.zendeskService.getRecentTickets(limit ? parseInt(limit) : 50);
  }
}
