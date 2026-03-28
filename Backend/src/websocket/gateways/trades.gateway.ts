import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  ConnectedSocket,
  MessageBody,
  WsException,
} from '@nestjs/websockets';
import { UseGuards, Logger } from '@nestjs/common';
import { Server, Socket } from 'socket.io';
import { WsJwtGuard } from '../ws-jwt.guard';
import { ConnectionStateService } from '../connection-state.service';
import { TradeNotificationPayload } from '../types/ws.types';

@WebSocketGateway({
  namespace: '/trades',
  cors: { origin: '*', credentials: true },
})
export class TradesGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(TradesGateway.name);

  constructor(private readonly connectionState: ConnectionStateService) {}

  async handleConnection(client: Socket) {
    const userId = client.handshake.query?.userId as string;
    if (userId) {
      this.connectionState.register(userId, client.id, 'trades');
      // Auto-join user's personal room for targeted notifications
      await client.join(`user:${userId}`);
    }
  }

  async handleDisconnect(client: Socket) {
    await this.connectionState.unregister(client.id);
  }

  /** Subscribe to trade updates for a specific asset pair */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('subscribe:trades')
  async subscribeTrades(@ConnectedSocket() client: Socket, @MessageBody() data: { asset: string }) {
    if (!data?.asset) throw new WsException('asset is required');

    const room = `trades:${data.asset.toUpperCase()}`;
    await client.join(room);
    this.connectionState.addRoom(client.id, room);

    return { event: 'subscribed', room };
  }

  /** Unsubscribe from trade updates */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('unsubscribe:trades')
  async unsubscribeTrades(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { asset: string },
  ) {
    if (!data?.asset) throw new WsException('asset is required');

    const room = `trades:${data.asset.toUpperCase()}`;
    await client.leave(room);
    this.connectionState.removeRoom(client.id, room);

    return { event: 'unsubscribed', room };
  }

  /** Send a trade notification to a specific user */
  notifyUser(userId: string, payload: TradeNotificationPayload): void {
    this.server.to(`user:${userId}`).emit('trade:notification', payload);
  }

  /** Broadcast a trade event to all subscribers of an asset */
  broadcastTrade(asset: string, payload: TradeNotificationPayload): void {
    const room = `trades:${asset.toUpperCase()}`;
    this.server.to(room).emit('trade:update', payload);
  }
}
