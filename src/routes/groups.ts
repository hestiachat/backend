import express, { Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

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

router.post(
  '/groups',
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
          createdAt: group.createdAt,
        });
      }

      res.status(201).json(group);
    } catch (error) {
      console.error('Error creating group:', error);
      res.status(500).json({ error: 'Failed to create group' });
    }
  })
);

router.get(
  '/groups',
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
      joinedAt: membership.joinedAt,
      createdAt: membership.group.createdAt,
      createdBy: membership.group.createdBy,
      creatorUsername: membership.group.creator.username,
    }));

    res.json(groups);
  })
);

router.get(
  '/groups/:id',
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
      createdAt: group.createdAt,
      createdBy: group.createdBy,
      creatorUsername: group.creator.username,
      memberCount: group._count.memberships,
      messageCount: group._count.messages,
      userRole: membership.role,
      members: group.memberships.map((member) => ({
        userId: member.user.id,
        username: member.user.username,
        role: member.role,
        joinedAt: member.joinedAt,
      })),
    });
  })
);

router.put(
  '/groups/:id',
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

    res.json(updatedGroup);
  })
);

router.post(
  '/groups/:id/members',
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
        joinedAt: membership.joinedAt,
      });
    }

    res.status(201).json({
      userId: membership.user.id,
      username: membership.user.username,
      role: membership.role,
      joinedAt: membership.joinedAt,
    });
  })
);

router.delete(
  '/groups/:id/members/:userId',
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
