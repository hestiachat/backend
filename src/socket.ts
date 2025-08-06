import { Server as SocketIOServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import { prisma } from './prismaClient';

const JWT_SECRET = process.env.JWT_SECRET!;

export function setupSocket(io: SocketIOServer) {
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentication error"));
    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return next(new Error("Authentication error"));
      (socket as any).user = user;
      next();
    });
  });

  io.on('connection', (socket) => {
    const user = (socket as any).user;
    console.log(`User connected: ${user.username}`);

    socket.on('joinGroup', (groupId: number) => {
      socket.join(`group_${groupId}`);
    });

    socket.on('leaveGroup', (groupId: number) => {
      socket.leave(`group_${groupId}`);
    });

    socket.on('sendMessage', async (data: { groupId: number; content: string }) => {
      try {
        const message = await prisma.message.create({
          data: {
            content: data.content,
            userId: user.userId,
            groupId: data.groupId,
          },
          include: { user: true },
        });

        io.to(`group_${data.groupId}`).emit('newMessage', {
          id: message.id,
          content: message.content,
          createdAt: message.createdAt,
          username: message.user.username,
        });
      } catch (e) {
        console.error(e);
      }
    });

    socket.on('disconnect', () => {
      console.log(`User disconnected: ${user.username}`);
    });
  });
}
