import { Injectable, Logger } from '@nestjs/common';
import { WebsocketLoadBalancerService } from './load-balancer.service';

interface SocketEntry {
  socketId: string;
  namespace: string;
  connectedAt: Date;
  rooms: Set<string>;
}

@Injectable()
export class ConnectionStateService {
  private readonly logger = new Logger(ConnectionStateService.name);

  constructor(
    private readonly loadBalancer: WebsocketLoadBalancerService,
  ) {}

  // userId -> list of socket entries (supports multiple tabs/devices)
  private readonly userSockets = new Map<string, SocketEntry[]>();
  // socketId -> userId (reverse lookup)
  private readonly socketUser = new Map<string, string>();

  async register(userId: string, socketId: string, namespace: string): Promise<void> {
    const entry: SocketEntry = {
      socketId,
      namespace,
      connectedAt: new Date(),
      rooms: new Set(),
    };

    const existing = this.userSockets.get(userId) || [];
    this.userSockets.set(userId, [...existing, entry]);
    this.socketUser.set(socketId, userId);

    await this.loadBalancer.reportConnectionChange(1);
    await this.loadBalancer.setUserMapping(userId);

    this.logger.log(`[${namespace}] User ${userId} connected (socket: ${socketId})`);
  }

  async unregister(socketId: string): Promise<void> {
    const userId = this.socketUser.get(socketId);
    if (!userId) return;

    const sockets = this.userSockets.get(userId) || [];
    const remaining = sockets.filter((s) => s.socketId !== socketId);

    if (remaining.length > 0) {
      this.userSockets.set(userId, remaining);
    } else {
      this.userSockets.delete(userId);
      await this.loadBalancer.removeUserMapping(userId);
    }

    this.socketUser.delete(socketId);
    await this.loadBalancer.reportConnectionChange(-1);

    this.logger.log(`User ${userId} disconnected (socket: ${socketId})`);
  }

  addRoom(socketId: string, room: string): void {
    const userId = this.socketUser.get(socketId);
    if (!userId) return;

    const sockets = this.userSockets.get(userId) || [];
    const entry = sockets.find((s) => s.socketId === socketId);
    if (entry) entry.rooms.add(room);
  }

  removeRoom(socketId: string, room: string): void {
    const userId = this.socketUser.get(socketId);
    if (!userId) return;

    const sockets = this.userSockets.get(userId) || [];
    const entry = sockets.find((s) => s.socketId === socketId);
    if (entry) entry.rooms.delete(room);
  }

  getSocketIds(userId: string, namespace?: string): string[] {
    const sockets = this.userSockets.get(userId) || [];
    return sockets.filter((s) => !namespace || s.namespace === namespace).map((s) => s.socketId);
  }

  getUserId(socketId: string): string | undefined {
    return this.socketUser.get(socketId);
  }

  isOnline(userId: string): boolean {
    return (this.userSockets.get(userId)?.length ?? 0) > 0;
  }

  getOnlineCount(): number {
    return this.userSockets.size;
  }

  getStats() {
    return {
      onlineUsers: this.userSockets.size,
      totalConnections: this.socketUser.size,
    };
  }
}
