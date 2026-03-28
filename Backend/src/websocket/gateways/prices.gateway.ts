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
import { PriceUpdatePayload } from '../types/ws.types';

@WebSocketGateway({
  namespace: '/prices',
  cors: { origin: '*', credentials: true },
})
export class PricesGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(PricesGateway.name);

  constructor(private readonly connectionState: ConnectionStateService) {}

  async handleConnection(client: Socket) {
    try {
      // Auth is handled per-message via guard, but we can do a lightweight check here
      const userId = client.handshake.query?.userId as string;
      if (userId) {
        await this.connectionState.register(userId, client.id, 'prices');
      }
    } catch {
      client.disconnect();
    }
  }

  async handleDisconnect(client: Socket) {
    await this.connectionState.unregister(client.id);
  }

  /** Subscribe to price updates for a specific asset (e.g. "XLM-USDC") */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('subscribe:asset')
  async subscribeAsset(@ConnectedSocket() client: Socket, @MessageBody() data: { asset: string }) {
    if (!data?.asset) throw new WsException('asset is required');

    const room = `prices:${data.asset.toUpperCase()}`;
    await client.join(room);
    this.connectionState.addRoom(client.id, room);

    this.logger.log(`Socket ${client.id} joined room ${room}`);
    return { event: 'subscribed', room };
  }

  /** Unsubscribe from a specific asset room */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('unsubscribe:asset')
  async unsubscribeAsset(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { asset: string },
  ) {
    if (!data?.asset) throw new WsException('asset is required');

    const room = `prices:${data.asset.toUpperCase()}`;
    await client.leave(room);
    this.connectionState.removeRoom(client.id, room);

    return { event: 'unsubscribed', room };
  }

  /** Broadcast a price update to all subscribers of an asset */
  broadcastPriceUpdate(asset: string, payload: PriceUpdatePayload): void {
    const room = `prices:${asset.toUpperCase()}`;
    this.server.to(room).emit('price:update', payload);
  }

  /** Broadcast to all connected clients in the namespace */
  broadcastAll(event: string, payload: any): void {
    this.server.emit(event, payload);
  }
}
