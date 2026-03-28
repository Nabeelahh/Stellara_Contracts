import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma.service';
import { ZendeskTicket, ZendeskStatus, ZendeskPriority } from '@prisma/client';

interface ZendeskApiTicket {
  id: number;
  subject: string;
  description: string;
  status: string;
  priority: string;
  assignee_id?: number;
  created_at: string;
  updated_at: string;
  custom_fields?: Array<{ id: number; value: string }>;
}

@Injectable()
export class ZendeskService {
  private readonly logger = new Logger(ZendeskService.name);
  private readonly baseUrl: string;
  private readonly username: string;
  private readonly apiToken: string;

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService
  ) {
    this.baseUrl = this.configService.get<string>('ZENDESK_BASE_URL');
    this.username = this.configService.get<string>('ZENDESK_USERNAME');
    this.apiToken = this.configService.get<string>('ZENDESK_API_TOKEN');

    if (!this.baseUrl || !this.username || !this.apiToken) {
      this.logger.warn('Zendesk configuration missing. Integration will be disabled.');
    }
  }

  private getAuthHeaders(): Record<string, string> {
    const auth = Buffer.from(`${this.username}/token:${this.apiToken}`).toString('base64');
    return {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/json',
    };
  }

  private mapZendeskStatus(status: string): ZendeskStatus {
    switch (status.toLowerCase()) {
      case 'open': return ZendeskStatus.OPEN;
      case 'pending': return ZendeskStatus.PENDING;
      case 'solved': return ZendeskStatus.SOLVED;
      case 'closed': return ZendeskStatus.CLOSED;
      default: return ZendeskStatus.OPEN;
    }
  }

  private mapZendeskPriority(priority: string): ZendeskPriority {
    switch (priority.toLowerCase()) {
      case 'low': return ZendeskPriority.LOW;
      case 'normal': return ZendeskPriority.NORMAL;
      case 'high': return ZendeskPriority.HIGH;
      case 'urgent': return ZendeskPriority.URGENT;
      default: return ZendeskPriority.NORMAL;
    }
  }

  async syncTicket(ticketId: number): Promise<ZendeskTicket | null> {
    if (!this.isConfigured()) {
      this.logger.warn('Zendesk not configured, skipping sync');
      return null;
    }

    try {
      const response = await fetch(`${this.baseUrl}/api/v2/tickets/${ticketId}.json`, {
        headers: this.getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Zendesk API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      const zendeskTicket: ZendeskApiTicket = data.ticket;

      // Find user by custom field or other identifier
      const userId = await this.findUserFromTicket(zendeskTicket);

      const ticket = await this.prisma.zendeskTicket.upsert({
        where: { ticketId },
        update: {
          subject: zendeskTicket.subject,
          description: zendeskTicket.description,
          status: this.mapZendeskStatus(zendeskTicket.status),
          priority: this.mapZendeskPriority(zendeskTicket.priority),
          assigneeId: zendeskTicket.assignee_id?.toString(),
          metadata: {
            zendeskData: zendeskTicket,
            lastSyncAt: new Date().toISOString()
          },
          updatedAt: new Date()
        },
        create: {
          ticketId: zendeskTicket.id,
          userId,
          subject: zendeskTicket.subject,
          description: zendeskTicket.description,
          status: this.mapZendeskStatus(zendeskTicket.status),
          priority: this.mapZendeskPriority(zendeskTicket.priority),
          assigneeId: zendeskTicket.assignee_id?.toString(),
          metadata: {
            zendeskData: zendeskTicket,
            createdAt: zendeskTicket.created_at
          }
        }
      });

      this.logger.log(`Synced Zendesk ticket ${ticketId}`);
      return ticket;

    } catch (error) {
      this.logger.error(`Failed to sync Zendesk ticket ${ticketId}:`, error);
      return null;
    }
  }

  async getTicketsForUser(userId: string): Promise<ZendeskTicket[]> {
    return this.prisma.zendeskTicket.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' }
    });
  }

  async createZendeskLink(userId: string, ticketId: number): Promise<ZendeskTicket> {
    // First sync the ticket from Zendesk
    const syncedTicket = await this.syncTicket(ticketId);
    
    if (!syncedTicket) {
      throw new Error('Failed to sync Zendesk ticket');
    }

    // Update with user link if not already linked
    if (!syncedTicket.userId) {
      return this.prisma.zendeskTicket.update({
        where: { id: syncedTicket.id },
        data: { userId }
      });
    }

    return syncedTicket;
  }

  async updateTicketStatus(ticketId: number, status: ZendeskStatus): Promise<void> {
    if (!this.isConfigured()) {
      this.logger.warn('Zendesk not configured, skipping update');
      return;
    }

    try {
      const zendeskStatus = this.reverseMapZendeskStatus(status);
      
      const response = await fetch(`${this.baseUrl}/api/v2/tickets/${ticketId}.json`, {
        method: 'PUT',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({
          ticket: {
            status: zendeskStatus
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Failed to update ticket status: ${response.status}`);
      }

      // Update local copy
      await this.prisma.zendeskTicket.update({
        where: { ticketId },
        data: { 
          status,
          updatedAt: new Date()
        }
      });

      this.logger.log(`Updated Zendesk ticket ${ticketId} status to ${status}`);

    } catch (error) {
      this.logger.error(`Failed to update Zendesk ticket ${ticketId} status:`, error);
      throw error;
    }
  }

  private async findUserFromTicket(ticket: ZendeskApiTicket): Promise<string | null> {
    // Try to find user by email in ticket description or custom fields
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = ticket.description.match(emailRegex);

    if (emails && emails.length > 0) {
      const user = await this.prisma.user.findFirst({
        where: { email: emails[0] }
      });
      
      if (user) {
        return user.id;
      }
    }

    // Try custom fields for user ID or wallet address
    if (ticket.custom_fields) {
      const userIdField = ticket.custom_fields.find(field => 
        field.value && (field.value.includes('user_') || field.value.startsWith('G'))
      );
      
      if (userIdField) {
        if (userIdField.value.startsWith('G')) {
          // Wallet address
          const user = await this.prisma.user.findFirst({
            where: { walletAddress: userIdField.value }
          });
          if (user) return user.id;
        } else if (userIdField.value.includes('user_')) {
          // User ID
          const userId = userIdField.value.replace('user_', '');
          const user = await this.prisma.user.findUnique({
            where: { id: userId }
          });
          if (user) return user.id;
        }
      }
    }

    return null;
  }

  private reverseMapZendeskStatus(status: ZendeskStatus): string {
    switch (status) {
      case ZendeskStatus.OPEN: return 'open';
      case ZendeskStatus.PENDING: return 'pending';
      case ZendeskStatus.SOLVED: return 'solved';
      case ZendeskStatus.CLOSED: return 'closed';
      default: return 'open';
    }
  }

  private isConfigured(): boolean {
    return !!(this.baseUrl && this.username && this.apiToken);
  }

  async getRecentTickets(limit = 50): Promise<ZendeskTicket[]> {
    return this.prisma.zendeskTicket.findMany({
      take: limit,
      orderBy: { createdAt: 'desc' },
      include: {
        user: true
      }
    });
  }
}
