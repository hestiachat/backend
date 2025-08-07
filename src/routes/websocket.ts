import { Socket, Server as SocketIOServer } from 'socket.io';
import { Server as HTTPServer } from 'http';
import jwt from 'jsonwebtoken';
import { prisma } from '../prismaClient';

interface AuthenticatedSocket extends Socket {
  userId?: number;
  username?: string;
}

export function setupWebSocket(server: HTTPServer) {
  const io = new SocketIOServer(server, {
    cors: {
      origin: process.env.CLIENT_URL || "http://localhost:3000",
      methods: ["GET", "POST"],
      credentials: true
    }
  });

  // Authentication middleware for WebSocket
  io.use(async (socket: any, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return next(new Error('Authentication error: No token provided'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: number };
      
      // Get user details
      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: { id: true, username: true }
      });

      if (!user) {
        return next(new Error('Authentication error: User not found'));
      }

      socket.userId = user.id;
      socket.username = user.username;
      next();
    } catch (error) {
      next(new Error('Authentication error: Invalid token'));
    }
  });

  io.on('connection', async (socket: AuthenticatedSocket) => {
    console.log(`User ${socket.username} (${socket.userId}) connected`);

    // Join user to their personal room for notifications
    socket.join(`user_${socket.userId}`);

    // Join user to all their DM rooms
    const friends = await prisma.friend.findMany({
      where: {
        OR: [
          { userId: socket.userId! },
          { friendId: socket.userId! }
        ]
      }
    });

    // Join DM rooms with friends
    for (const friend of friends) {
      const friendId = friend.userId === socket.userId ? friend.friendId : friend.userId;
      const roomName = `dm_${Math.min(socket.userId!, friendId)}_${Math.max(socket.userId!, friendId)}`;
      socket.join(roomName);
    }

    // Join group rooms
    const groupMemberships = await prisma.groupMembership.findMany({
      where: { userId: socket.userId! }
    });

    for (const membership of groupMemberships) {
      socket.join(`group_${membership.groupId}`);
    }

    // Handle joining specific DM room when user opens a chat
    socket.on('joinDM', (friendId: number) => {
      const roomName = `dm_${Math.min(socket.userId!, friendId)}_${Math.max(socket.userId!, friendId)}`;
      socket.join(roomName);
      console.log(`${socket.username} joined DM room: ${roomName}`);
    });

    // Handle leaving DM room
    socket.on('leaveDM', (friendId: number) => {
      const roomName = `dm_${Math.min(socket.userId!, friendId)}_${Math.max(socket.userId!, friendId)}`;
      socket.leave(roomName);
      console.log(`${socket.username} left DM room: ${roomName}`);
    });

    // Handle joining group room
    socket.on('joinGroup', async (groupId: number) => {
      // Verify membership
      const isMember = await prisma.groupMembership.findFirst({
        where: { groupId, userId: socket.userId! }
      });

      if (isMember) {
        socket.join(`group_${groupId}`);
        console.log(`${socket.username} joined group room: group_${groupId}`);
      }
    });

    // Handle leaving group room
    socket.on('leaveGroup', (groupId: number) => {
      socket.leave(`group_${groupId}`);
      console.log(`${socket.username} left group room: group_${groupId}`);
    });

    // Handle typing indicators for DMs
    socket.on('typing', (data: { friendId: number; isTyping: boolean }) => {
      const roomName = `dm_${Math.min(socket.userId!, data.friendId)}_${Math.max(socket.userId!, data.friendId)}`;
      socket.to(roomName).emit('userTyping', {
        userId: socket.userId,
        username: socket.username,
        isTyping: data.isTyping
      });
    });

    // Handle typing indicators for groups
    socket.on('groupTyping', (data: { groupId: number; isTyping: boolean }) => {
      socket.to(`group_${data.groupId}`).emit('userTyping', {
        userId: socket.userId,
        username: socket.username,
        isTyping: data.isTyping
      });
    });

    // Handle user presence/status updates
    socket.on('updateStatus', (status: 'online' | 'away' | 'busy' | 'offline') => {
      // Broadcast status to all friends
      socket.broadcast.emit('userStatusUpdate', {
        userId: socket.userId,
        username: socket.username,
        status
      });
    });

    socket.on('disconnect', () => {
      console.log(`User ${socket.username} (${socket.userId}) disconnected`);
      
      // Broadcast offline status to friends
      socket.broadcast.emit('userStatusUpdate', {
        userId: socket.userId,
        username: socket.username,
        status: 'offline'
      });
    });

    // Handle errors
    socket.on('error', (error) => {
      console.error(`Socket error for user ${socket.username}:`, error);
    });
  });

  return io;
}