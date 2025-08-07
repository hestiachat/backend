// routes/friends.ts

import express, { Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';

const router = express.Router();

// Wysyłanie zaproszenia
router.post('/friends/request/:id', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const targetId = parseInt(req.params.id);
  const userId = req.user!.userId;

  if (targetId === userId) {
    res.status(400).json({ error: 'Cannot send request to yourself' });
    return;
  }

  // Check if target user exists
  const targetUser = await prisma.user.findUnique({ where: { id: targetId } });
  if (!targetUser) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // Check if already friends
  const areFriends = await prisma.friend.findFirst({
    where: {
      userId: userId,
      friendId: targetId,
    },
  });
  if (areFriends) {
    res.status(400).json({ error: 'Already friends' });
    return;
  }

  const existing = await prisma.friendRequest.findFirst({
    where: {
      OR: [
        { fromId: userId, toId: targetId },
        { fromId: targetId, toId: userId },
      ],
    },
  });

  if (existing) {
    res.status(400).json({ error: 'Friend request already exists' });
    return;
  }

  await prisma.friendRequest.create({
    data: {
      fromId: userId,
      toId: targetId,
    },
  });

  res.json({ success: true });
}));


// Akceptowanie zaproszenia
router.post('/friends/accept/:id', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const fromId = parseInt(req.params.id);
  const toId = req.user!.userId;

  const request = await prisma.friendRequest.findFirst({
    where: { fromId, toId },
  });

  if (!request) {
    res.status(404).json({ error: 'Friend request not found' });
    return;
  }

  await prisma.$transaction([
    prisma.friendRequest.delete({ where: { id: request.id } }),
    prisma.friend.createMany({
      data: [
        { userId: fromId, friendId: toId },
        { userId: toId, friendId: fromId },
      ],
      skipDuplicates: true,
    }),
  ]);

  res.json({ success: true });
}));

// Pobieranie listy znajomych
router.get('/friends', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user!.userId;

  const friends = await prisma.friend.findMany({
    where: { userId },
    include: {
      friend: {
        select: { id: true, username: true },
      },
    },
  });

  res.json(friends.map((f: { friend: any; }) => f.friend));
}));

// Zapytania oczekujące
router.get('/friends/requests', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user!.userId;

  const requests = await prisma.friendRequest.findMany({
    where: { toId: userId },
    include: {
      from: {
        select: { id: true, username: true },
      },
    },
  });

  res.json(requests.map(r => r.from));
}));

export default router;
