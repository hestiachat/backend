import express, { Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

const router = express.Router();

// Group message validation
const messageSchema = z.object({
  content: z.string().min(1).max(2048),
  groupId: z.number().int().positive(),
});

/**
 * POST /messages
 * Send a message to a group (requires auth).
 * Body: { groupId: number, content: string }
 */
router.post(
  '/messages',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res) => {
    const parse = messageSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }
    const { groupId, content } = parse.data;

    // Check membership
    const isMember = await prisma.groupMembership.findFirst({
      where: { groupId, userId: req.user!.userId },
    });
    if (!isMember) {
      res.status(403).json({ error: 'Not a group member' });
      return;
    }

    // Create message
    const message = await prisma.message.create({
      data: {
        content,
        userId: req.user!.userId,
        groupId,
      },
      include: { user: { select: { username: true } } },
    });

    // Emit Socket.IO if present
    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('newMessage', {
        id: message.id,
        content: message.content,
        createdAt: message.createdAt,
        userId: message.userId,
        username: message.user.username,
        groupId: groupId,
      });
    }

    res.status(201).json({
      id: message.id,
      content: message.content,
      createdAt: message.createdAt,
      userId: message.userId,
      username: message.user.username,
    });
  })
);

// POST /dm/:id/messages — Send a direct message
router.post('/dm/:id/messages', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const fromId = req.user!.userId;
  const toId = parseInt(req.params.id, 10);
  const { content } = req.body;

  if (!content || typeof content !== 'string' || !content.trim()) {
    res.status(400).json({ error: 'Content is required' });
    return;
  }
  if (fromId === toId) {
    res.status(400).json({ error: 'Cannot send DM to yourself' });
    return;
  }

  // Check if users are friends (without status field)
  const friendship = await prisma.friend.findFirst({
    where: {
      OR: [
        { userId: fromId, friendId: toId },
        { userId: toId, friendId: fromId }
      ]
    }
  });

  if (!friendship) {
    res.status(403).json({ error: 'You can only send messages to friends' });
    return;
  }

  // Check if recipient exists
  const recipient = await prisma.user.findUnique({
    where: { id: toId },
    select: { id: true, username: true }
  });

  if (!recipient) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const message = await prisma.message.create({
    data: {
      content: content.trim(),
      userId: fromId,      // sender
      recipientId: toId,   // recipient
    },
    include: { user: { select: { username: true } } },
  });

  // Create consistent room names for DMs (smaller ID first)
  const roomName = `dm_${Math.min(fromId, toId)}_${Math.max(fromId, toId)}`;

  // Emit with Socket.IO to both users
  if (req.app.get('io')) {
    const io = req.app.get('io');
    
    const messageData = {
      id: message.id,
      content: message.content,
      createdAt: message.createdAt,
      userId: message.userId,
      username: message.user.username,
      recipientId: toId,
    };

    // Emit to the DM room
    io.to(roomName).emit('newDM', messageData);
    
    // Also emit to individual user rooms for notifications
    io.to(`user_${toId}`).emit('dmNotification', {
      ...messageData,
      senderId: fromId,
      senderUsername: message.user.username,
    });
  }

  res.status(201).json({
    id: message.id,
    content: message.content,
    createdAt: message.createdAt,
    userId: message.userId,
    username: message.user.username,
  });
}));

// GET /dm/:id/messages — Get all DMs between current user and :id
router.get('/dm/:id/messages', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const me = req.user!.userId;
  const other = parseInt(req.params.id, 10);

  if (isNaN(other)) {
    res.status(400).json({ error: 'Invalid user ID' });
    return;
  }

  // Check if users are friends (without status field)
  const friendship = await prisma.friend.findFirst({
    where: {
      OR: [
        { userId: me, friendId: other },
        { userId: other, friendId: me }
      ]
    }
  });

  if (!friendship) {
    res.status(403).json({ error: 'You can only view messages with friends' });
    return;
  }

  const messages = await prisma.message.findMany({
    where: {
      AND: [
        { groupId: null }, // Only DMs, not group messages
        {
          OR: [
            { userId: me, recipientId: other },
            { userId: other, recipientId: me }
          ]
        }
      ]
    },
    orderBy: { createdAt: 'asc' },
    include: { user: { select: { username: true } } }
  });

  res.json(messages.map((msg: { id: any; content: any; createdAt: any; userId: any; user: { username: any; }; }) => ({
    id: msg.id,
    content: msg.content,
    createdAt: msg.createdAt,
    userId: msg.userId,
    username: msg.user.username
  })));
}));

// GET /messages/:groupId — Get group messages
router.get('/messages/:groupId', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const groupId = parseInt(req.params.groupId, 10);
  const userId = req.user!.userId;

  if (isNaN(groupId)) {
    res.status(400).json({ error: 'Invalid group ID' });
    return;
  }

  // Check membership
  const isMember = await prisma.groupMembership.findFirst({
    where: { groupId, userId },
  });

  if (!isMember) {
    res.status(403).json({ error: 'Not a group member' });
    return;
  }

  const messages = await prisma.message.findMany({
    where: { groupId },
    orderBy: { createdAt: 'asc' },
    include: { user: { select: { username: true } } }
  });

  res.json(messages.map((msg: { id: any; content: any; createdAt: any; userId: any; user: { username: any; }; groupId: any; }) => ({
    id: msg.id,
    content: msg.content,
    createdAt: msg.createdAt,
    userId: msg.userId,
    username: msg.user.username,
    groupId: msg.groupId
  })));
}));

export default router;