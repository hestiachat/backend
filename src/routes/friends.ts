import express, { Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';

const router = express.Router();

// Wysyłanie zaproszenia
router.post(
  '/request/:id',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
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
        userId,
        friendId: targetId,
      },
    });
    if (areFriends) {
      res.status(400).json({ error: 'Already friends' });
      return;
    }

    // Check if friend request already exists
    const existing = await prisma.friendRequest.findFirst({
      where: {
        OR: [
          { senderId: userId, receiverId: targetId },
          { senderId: targetId, receiverId: userId },
        ],
      },
    });

    if (existing) {
      res.status(400).json({ error: 'Friend request already exists' });
      return;
    }

    await prisma.friendRequest.create({
      data: {
        senderId: userId,
        receiverId: targetId,
        status: 'pending',
      },
    });

    res.json({ success: true });
  })
);

// Akceptowanie zaproszenia
router.post(
  '/accept/:id',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const senderId = parseInt(req.params.id);
    const receiverId = req.user!.userId;

    const request = await prisma.friendRequest.findFirst({
      where: { senderId, receiverId, status: 'pending' },
    });

    if (!request) {
      res.status(404).json({ error: 'Friend request not found' });
      return;
    }

    await prisma.$transaction([
      prisma.friendRequest.delete({ where: { id: request.id } }),
      prisma.friend.createMany({
        data: [
          { userId: senderId, friendId: receiverId },
          { userId: receiverId, friendId: senderId },
        ],
        skipDuplicates: true,
      }),
    ]);

    res.json({ success: true });
  })
);

// Pobieranie listy znajomych
router.get(
  '',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.userId;

    const friends = await prisma.friend.findMany({
      where: { userId },
      include: {
        friend: {
          select: { id: true, username: true },
        },
      },
    });

    res.json(friends.map((f) => f.friend));
  })
);

// Zapytania oczekujące
router.get(
  '/requests',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.userId;

    const requests = await prisma.friendRequest.findMany({
      where: { receiverId: userId, status: 'pending' },
      include: {
        sender: {
          select: { id: true, username: true },
        },
      },
    });

    res.json(requests.map((r) => r.sender));
  })
);

export default router;
