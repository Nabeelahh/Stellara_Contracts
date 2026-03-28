import {
  ConnectedSocket,
  MessageBody,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
  WsException,
} from '@nestjs/websockets';
import { Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({
  namespace: '/analytics',
  cors: { origin: '*', credentials: true },
})
export class RealtimeAnalyticsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(RealtimeAnalyticsGateway.name);

  async handleConnection(client: Socket): Promise<void> {
    await client.join('analytics:global');
  }

  async handleDisconnect(_client: Socket): Promise<void> {
    // No-op for now, connection stats can be added later.
  }

  @SubscribeMessage('subscribe:metrics')
  async subscribeMetrics(
    @ConnectedSocket() client: Socket,
    @MessageBody() data?: { channel?: string },
  ): Promise<{ event: string; room: string }> {
    const channel = (data?.channel || 'global').trim().toLowerCase();
    if (!channel) {
      throw new WsException('channel is required');
    }

    const room = `analytics:${channel}`;
    await client.join(room);
    return { event: 'subscribed', room };
  }

  @SubscribeMessage('unsubscribe:metrics')
  async unsubscribeMetrics(
    @ConnectedSocket() client: Socket,
    @MessageBody() data?: { channel?: string },
  ): Promise<{ event: string; room: string }> {
    const channel = (data?.channel || 'global').trim().toLowerCase();
    const room = `analytics:${channel}`;
    await client.leave(room);
    return { event: 'unsubscribed', room };
  }

  broadcastGlobal(payload: unknown): void {
    this.server.to('analytics:global').emit('metrics:update', payload);
  }

  broadcastChannel(channel: string, payload: unknown): void {
    const room = `analytics:${channel.toLowerCase()}`;
    this.server.to(room).emit('metrics:update', payload);
  }

  emitRollupRefresh(payload: unknown): void {
    this.server.to('analytics:global').emit('rollups:refresh', payload);
  }
}

