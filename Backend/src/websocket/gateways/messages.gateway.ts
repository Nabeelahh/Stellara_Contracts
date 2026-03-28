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
import { MessagePayload } from '../types/ws.types';

@WebSocketGateway({
  namespace: '/messages',
  cors: { origin: '*', credentials: true },
})
export class MessagesGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(MessagesGateway.name);

  constructor(private readonly connectionState: ConnectionStateService) {}

  async handleConnection(client: Socket) {
    const userId = client.handshake.query?.userId as string;
    if (userId) {
      await this.connectionState.register(userId, client.id, 'messages');
      // Auto-join personal room
      await client.join(`user:${userId}`);
    }
  }

  async handleDisconnect(client: Socket) {
    await this.connectionState.unregister(client.id);
  }

  /** Join a named chat room */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('room:join')
  async joinRoom(@ConnectedSocket() client: Socket, @MessageBody() data: { room: string }) {
    if (!data?.room) throw new WsException('room is required');

    const room = `room:${data.room}`;
    await client.join(room);
    this.connectionState.addRoom(client.id, room);

    // Notify others in the room
    client.to(room).emit('room:user_joined', {
      userId: client.data.user?.id,
      room: data.room,
      timestamp: Date.now(),
    });

    return { event: 'joined', room: data.room };
  }

  /** Leave a named chat room */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('room:leave')
  async leaveRoom(@ConnectedSocket() client: Socket, @MessageBody() data: { room: string }) {
    if (!data?.room) throw new WsException('room is required');

    const room = `room:${data.room}`;
    await client.leave(room);
    this.connectionState.removeRoom(client.id, room);

    client.to(room).emit('room:user_left', {
      userId: client.data.user?.id,
      room: data.room,
      timestamp: Date.now(),
    });

    return { event: 'left', room: data.room };
  }

  /** Send a message to a room */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('message:send')
  async sendMessage(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { room: string; content: string },
  ) {
    if (!data?.room || !data?.content) {
      throw new WsException('room and content are required');
    }

    const user = client.data.user;
    const payload: MessagePayload = {
      messageId: `${Date.now()}-${client.id}`,
      senderId: user?.id,
      room: data.room,
      content: data.content,
      timestamp: Date.now(),
    };

    const room = `room:${data.room}`;
    // Broadcast to room (including sender)
    this.server.to(room).emit('message:received', payload);

    return { event: 'sent', messageId: payload.messageId };
  }

  /** Send a direct message to a specific user */
  @UseGuards(WsJwtGuard)
  @SubscribeMessage('message:direct')
  async sendDirect(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { recipientId: string; content: string },
  ) {
    if (!data?.recipientId || !data?.content) {
      throw new WsException('recipientId and content are required');
    }

    const user = client.data.user;
    const payload: MessagePayload = {
      messageId: `${Date.now()}-${client.id}`,
      senderId: user?.id,
      recipientId: data.recipientId,
      content: data.content,
      timestamp: Date.now(),
    };

    // Send to recipient's personal room
    this.server.to(`user:${data.recipientId}`).emit('message:received', payload);
    // Echo back to sender
    client.emit('message:sent', payload);

    return { event: 'sent', messageId: payload.messageId };
  }

  /** Programmatically send a message to a user (used by other services) */
  sendToUser(userId: string, event: string, payload: any): void {
    this.server.to(`user:${userId}`).emit(event, payload);
  }
}
