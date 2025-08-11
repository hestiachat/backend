import express, { Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';
import crypto from 'crypto';

const router = express.Router();

const createGroupSchema = z.object({
  name: z.string().min(1).max(100).trim(),
  description: z.string().max(500).optional(),
  isPrivate: z.boolean().default(false),
});

const updateGroupSchema = z.object({
  name: z.string().min(1).max(100).trim().optional(),
  description: z.string().max(500).optional(),
  isPrivate: z.boolean().optional(),
});

const addMemberSchema = z.object({
  userId: z.number().int().positive(),
  role: z.enum(['MEMBER', 'ADMIN']).default('MEMBER'),
});

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

const getEncryptionKey = (): Buffer => {
  if (!ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY environment variable is not set!');
  }
  if (ENCRYPTION_KEY.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be 64 characters (32 bytes in hex)');
  }
  return Buffer.from(ENCRYPTION_KEY, 'hex');
};


const encryptMessage = (text: string): { encrypted: string; iv: string; authTag: string } => {
  const iv = crypto.randomBytes(12);
  const key = getEncryptionKey();
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

  cipher.setAAD(Buffer.from('message', 'utf8'));

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
};

const decryptMessage = (encryptedData: { encrypted: string; iv: string; authTag: string }): string => {
  try {
    const key = getEncryptionKey();
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);

    decipher.setAAD(Buffer.from('message', 'utf8'));
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Decryption failed:', error);
    return '[Message could not be decrypted]';
  }
};

router.post(
  '/',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const parse = createGroupSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'Invalid input', details: parse.error.issues });
      return;
    }

    const { name, description, isPrivate } = parse.data;
    const userId = req.user!.userId;

    try {
      const group = await prisma.$transaction(async (tx) => {
        const newGroup = await tx.group.create({
          data: { name, description, isPrivate, createdBy: userId },
        });

        await tx.groupMembership.create({
          data: { groupId: newGroup.id, userId, role: 'ADMIN' },
        });

        return newGroup;
      });

      if (req.app.get('io')) {
        const io = req.app.get('io');
        io.to(`user_${userId}`).emit('groupCreated', {
          id: group.id,
          name: group.name,
          description: group.description,
          isPrivate: group.isPrivate,
          createdAt: new Date(group.createdAt).getTime(), // Unix timestamp
        });
      }

      res.status(201).json({
        ...group,
        createdAt: new Date(group.createdAt).getTime(), // Unix timestamp
      });
    } catch (error) {
      console.error('Error creating group:', error);
      res.status(500).json({ error: 'Failed to create group' });
    }
  })
);

router.get(
  '/',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.userId;

    const memberships = await prisma.groupMembership.findMany({
      where: { userId },
      include: {
        group: {
          include: {
            _count: { select: { memberships: true } },
            creator: { select: { username: true } },
          },
        },
      },
    });

    const groups = memberships.map((membership) => ({
      id: membership.group.id,
      name: membership.group.name,
      description: membership.group.description,
      isPrivate: membership.group.isPrivate,
      memberCount: membership.group._count.memberships,
      role: membership.role,
      joinedAt: new Date(membership.joinedAt).getTime(), // Unix timestamp
      createdAt: new Date(membership.group.createdAt).getTime(), // Unix timestamp
      createdBy: membership.group.createdBy,
      creatorUsername: membership.group.creator.username,
    }));

    res.json(groups);
  })
);

// POST /groups/:id/messages — Send a message to a group by ID
router.post(
  '/:id/messages',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const userId = req.user!.userId;
    const { content } = req.body;

    // Validate input
    if (isNaN(groupId)) {
      res.status(400).json({ error: 'Invalid group ID' });
      return;
    }
    if (!content || typeof content !== 'string' || !content.trim()) {
      res.status(400).json({ error: 'Content is required' });
      return;
    }
    if (content.length > 2048) {
      res.status(400).json({ error: 'Message too long' });
      return;
    }

    // Membership check
    const isMember = await prisma.groupMembership.findFirst({
      where: { groupId, userId },
    });
    if (!isMember) {
      res.status(403).json({ error: 'Not a group member' });
      return;
    }

    // Encrypt the message
    // Import encryptMessage from messages.ts if necessary:
    // If in same repo, use the same function or move the util to a shared file.
    // Here, we'll assume encryptMessage is accessible.
    const encryptedData = encryptMessage(content.trim());

    // Create message
    const message = await prisma.message.create({
      data: {
        content: encryptedData.encrypted,
        iv: encryptedData.iv,
        authTag: encryptedData.authTag,
        userId,
        groupId,
      },
      include: { user: { select: { username: true } } },
    });

    // Emit Socket.IO if present
    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('newMessage', {
        id: message.id,
        content: content.trim(),
        createdAt: message.createdAt.getTime(),
        userId: message.userId,
        username: message.user.username,
        groupId: groupId,
      });
    }

    res.status(201).json({
      id: message.id,
      content: content.trim(),
      createdAt: message.createdAt.getTime(),
      userId: message.userId,
      username: message.user.username,
      groupId: groupId,
    });
  })
);

router.get(
  '/:id',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const userId = req.user!.userId;

    if (isNaN(groupId)) {
      res.status(400).json({ error: 'Invalid group ID' });
      return;
    }

    const membership = await prisma.groupMembership.findFirst({
      where: { groupId, userId },
    });
    if (!membership) {
      res.status(403).json({ error: 'Not a group member' });
      return;
    }

    const group = await prisma.group.findUnique({
      where: { id: groupId },
      include: {
        creator: { select: { username: true } },
        _count: { select: { memberships: true, messages: true } },
        memberships: {
          include: { user: { select: { id: true, username: true } } },
          orderBy: { joinedAt: 'asc' },
        },
      },
    });

    if (!group) {
      res.status(404).json({ error: 'Group not found' });
      return;
    }

    res.json({
      id: group.id,
      name: group.name,
      description: group.description,
      isPrivate: group.isPrivate,
      createdAt: new Date(group.createdAt).getTime(), // Unix timestamp
      createdBy: group.createdBy,
      creatorUsername: group.creator.username,
      memberCount: group._count.memberships,
      messageCount: group._count.messages,
      userRole: membership.role,
      members: group.memberships.map((member) => ({
        userId: member.user.id,
        username: member.user.username,
        role: member.role,
        joinedAt: new Date(member.joinedAt).getTime(), // Unix timestamp
      })),
    });
  })
);

router.put(
  '/:id',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const userId = req.user!.userId;

    if (isNaN(groupId)) {
      res.status(400).json({ error: 'Invalid group ID' });
      return;
    }

    const parse = updateGroupSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'Invalid input', details: parse.error.issues });
      return;
    }

    const membership = await prisma.groupMembership.findFirst({
      where: { groupId, userId, role: 'ADMIN' },
    });
    if (!membership) {
      res.status(403).json({ error: 'Admin access required' });
      return;
    }

    const updatedGroup = await prisma.group.update({
      where: { id: groupId },
      data: parse.data,
    });

    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('groupUpdated', {
        id: updatedGroup.id,
        name: updatedGroup.name,
        description: updatedGroup.description,
        isPrivate: updatedGroup.isPrivate,
        updatedBy: userId,
      });
    }

    res.json({
      ...updatedGroup,
      createdAt: new Date(updatedGroup.createdAt).getTime(), // Unix timestamp
    });
  })
);

router.post(
  '/:id/members',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const currentUserId = req.user!.userId;

    if (isNaN(groupId)) {
      res.status(400).json({ error: 'Invalid group ID' });
      return;
    }

    const parse = addMemberSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: 'Invalid input', details: parse.error.issues });
      return;
    }

    const { userId, role } = parse.data;

    const adminMembership = await prisma.groupMembership.findFirst({
      where: { groupId, userId: currentUserId, role: 'ADMIN' },
    });
    if (!adminMembership) {
      res.status(403).json({ error: 'Admin access required' });
      return;
    }

    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true },
    });
    if (!targetUser) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const existingMembership = await prisma.groupMembership.findFirst({
      where: { groupId, userId },
    });
    if (existingMembership) {
      res.status(409).json({ error: 'User is already a member' });
      return;
    }

    const membership = await prisma.groupMembership.create({
      data: { groupId, userId, role },
      include: { user: { select: { id: true, username: true } } },
    });

    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('memberAdded', {
        userId: membership.user.id,
        username: membership.user.username,
        role: membership.role,
        joinedAt: new Date(membership.joinedAt).getTime(), // Unix timestamp
      });
    }

    res.status(201).json({
      userId: membership.user.id,
      username: membership.user.username,
      role: membership.role,
      joinedAt: new Date(membership.joinedAt).getTime(), // Unix timestamp
    });
  })
);

router.delete(
  '/:id/members/:userId',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const currentUserId = req.user!.userId;
    const userIdToRemove = parseInt(req.params.userId, 10);

    if (isNaN(groupId) || isNaN(userIdToRemove)) {
      res.status(400).json({ error: 'Invalid IDs' });
      return;
    }

    const adminMembership = await prisma.groupMembership.findFirst({
      where: { groupId, userId: currentUserId, role: 'ADMIN' },
    });
    if (!adminMembership) {
      res.status(403).json({ error: 'Admin access required' });
      return;
    }

    if (userIdToRemove === currentUserId) {
      res.status(403).json({ error: 'Admins cannot remove themselves' });
      return;
    }

    const membership = await prisma.groupMembership.findFirst({
      where: { groupId, userId: userIdToRemove },
    });
    if (!membership) {
      res.status(404).json({ error: 'User is not a member' });
      return;
    }

    await prisma.groupMembership.delete({ where: { id: membership.id } });

    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('memberRemoved', { userId: userIdToRemove });
    }

    res.json({ message: 'User removed from group' });
  })
);

export default router;