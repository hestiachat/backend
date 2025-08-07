import express, { Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

const router = express.Router();

// Group creation validation
const createGroupSchema = z.object({
  name: z.string().min(1).max(100).trim(),
  description: z.string().max(500).optional(),
  isPrivate: z.boolean().default(false),
});

// Group update validation
const updateGroupSchema = z.object({
  name: z.string().min(1).max(100).trim().optional(),
  description: z.string().max(500).optional(),
  isPrivate: z.boolean().optional(),
});

// Add member validation
const addMemberSchema = z.object({
  userId: z.number().int().positive(),
  role: z.enum(['MEMBER', 'ADMIN']).default('MEMBER'),
});

/**
 * POST /groups
 * Create a new group (requires auth).
 * Body: { name: string, description?: string, isPrivate?: boolean }
 */
router.post(
  '/groups',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const parse = createGroupSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ 
        error: 'Invalid input', 
        details: parse.error.issues 
      });
      return;
    }

    const { name, description, isPrivate } = parse.data;
    const userId = req.user!.userId;

    try {
      // Create group and add creator as admin in a transaction
      const result = await prisma.$transaction(async (tx: { group: { create: (arg0: { data: { name: string; description: string | undefined; isPrivate: boolean; createdBy: number; }; }) => any; }; groupMembership: { create: (arg0: { data: { groupId: any; userId: number; role: string; }; }) => any; }; }) => {
        // Create the group
        const group = await tx.group.create({
          data: {
            name,
            description,
            isPrivate,
            createdBy: userId,
          },
        });

        // Add creator as admin
        await tx.groupMembership.create({
          data: {
            groupId: group.id,
            userId,
            role: 'ADMIN',
          },
        });

        return group;
      });

      // Emit WebSocket event if available
      if (req.app.get('io')) {
        const io = req.app.get('io');
        io.to(`user_${userId}`).emit('groupCreated', {
          id: result.id,
          name: result.name,
          description: result.description,
          isPrivate: result.isPrivate,
          createdAt: result.createdAt,
        });
      }

      res.status(201).json({
        id: result.id,
        name: result.name,
        description: result.description,
        isPrivate: result.isPrivate,
        createdAt: result.createdAt,
        createdBy: result.createdBy,
      });
    } catch (error) {
      console.error('Error creating group:', error);
      res.status(500).json({ error: 'Failed to create group' });
    }
  })
);

/**
 * GET /groups
 * Get all groups user is a member of
 */
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
            _count: {
              select: { members: true }
            },
            creator: {
              select: { username: true }
            }
          }
        }
      },
      orderBy: { joinedAt: 'desc' }
    });

    const groups = memberships.map((membership: { group: { id: any; name: any; description: any; isPrivate: any; _count: { members: any; }; createdAt: any; createdBy: any; creator: { username: any; }; }; role: any; joinedAt: any; }) => ({
      id: membership.group.id,
      name: membership.group.name,
      description: membership.group.description,
      isPrivate: membership.group.isPrivate,
      memberCount: membership.group._count.members,
      role: membership.role,
      joinedAt: membership.joinedAt,
      createdAt: membership.group.createdAt,
      createdBy: membership.group.createdBy,
      creatorUsername: membership.group.creator.username,
    }));

    res.json(groups);
  })
);

/**
 * GET /groups/:id
 * Get group details (if user is a member)
 */
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

    // Check if user is a member
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
        members: {
          include: {
            user: {
              select: { id: true, username: true }
            }
          },
          orderBy: { joinedAt: 'asc' }
        },
        creator: {
          select: { username: true }
        },
        _count: {
          select: { 
            members: true,
            messages: true 
          }
        }
      }
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
      memberCount: group._count.members,
      messageCount: group._count.messages,
      userRole: membership.role,
      members: group.members.map((member: { user: { id: any; username: any; }; role: any; joinedAt: any; }) => ({
        userId: member.user.id,
        username: member.user.username,
        role: member.role,
        joinedAt: member.joinedAt,
      })),
    });
  })
);

/**
 * PUT /groups/:id
 * Update group details (admin only)
 */
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
      res.status(400).json({ 
        error: 'Invalid input', 
        details: parse.error.issues 
      });
      return;
    }

    // Check if user is an admin
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

    // Emit WebSocket event
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
      id: updatedGroup.id,
      name: updatedGroup.name,
      description: updatedGroup.description,
      isPrivate: updatedGroup.isPrivate,
      updatedAt: updatedGroup.updatedAt,
    });
  })
);

/**
 * POST /groups/:id/members
 * Add a member to the group (admin only)
 */
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
      res.status(400).json({ 
        error: 'Invalid input', 
        details: parse.error.issues 
      });
      return;
    }

    const { userId, role } = parse.data;

    // Check if current user is an admin
    const adminMembership = await prisma.groupMembership.findFirst({
      where: { groupId, userId: currentUserId, role: 'ADMIN' },
    });

    if (!adminMembership) {
      res.status(403).json({ error: 'Admin access required' });
      return;
    }

    // Check if target user exists
    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, username: true }
    });

    if (!targetUser) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // Check if user is already a member
    const existingMembership = await prisma.groupMembership.findFirst({
      where: { groupId, userId },
    });

    if (existingMembership) {
      res.status(409).json({ error: 'User is already a member' });
      return;
    }

    const membership = await prisma.groupMembership.create({
      data: {
        groupId,
        userId,
        role,
      },
    });

    // Emit WebSocket events
    if (req.app.get('io')) {
      const io = req.app.get('io');
      
      // Notify the group
      io.to(`group_${groupId}`).emit('memberAdded', {
        groupId,
        userId,
        username: targetUser.username,
        role,
        addedBy: currentUserId,
      });

      // Notify the new member
      io.to(`user_${userId}`).emit('addedToGroup', {
        groupId,
        role,
        addedBy: currentUserId,
      });
    }

    res.status(201).json({
      userId,
      username: targetUser.username,
      role,
      joinedAt: membership.joinedAt,
    });
  })
);

/**
 * DELETE /groups/:id/members/:userId
 * Remove a member from the group (admin only, or self-leave)
 */
router.delete(
  '/groups/:id/members/:userId',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const targetUserId = parseInt(req.params.userId, 10);
    const currentUserId = req.user!.userId;

    if (isNaN(groupId) || isNaN(targetUserId)) {
      res.status(400).json({ error: 'Invalid IDs' });
      return;
    }

    const isSelfLeave = currentUserId === targetUserId;

    if (!isSelfLeave) {
      // Check if current user is an admin
      const adminMembership = await prisma.groupMembership.findFirst({
        where: { groupId, userId: currentUserId, role: 'ADMIN' },
      });

      if (!adminMembership) {
        res.status(403).json({ error: 'Admin access required' });
        return;
      }
    }

    // Check if target user is a member
    const membership = await prisma.groupMembership.findFirst({
      where: { groupId, userId: targetUserId },
    });

    if (!membership) {
      res.status(404).json({ error: 'User is not a member' });
      return;
    }

    // Prevent removing the last admin
    if (membership.role === 'ADMIN') {
      const adminCount = await prisma.groupMembership.count({
        where: { groupId, role: 'ADMIN' },
      });

      if (adminCount === 1) {
        res.status(400).json({ error: 'Cannot remove the last admin' });
        return;
      }
    }

    await prisma.groupMembership.delete({
      where: { id: membership.id },
    });

    // Emit WebSocket events
    if (req.app.get('io')) {
      const io = req.app.get('io');
      
      io.to(`group_${groupId}`).emit('memberRemoved', {
        groupId,
        userId: targetUserId,
        removedBy: currentUserId,
        isLeave: isSelfLeave,
      });

      io.to(`user_${targetUserId}`).emit('removedFromGroup', {
        groupId,
        removedBy: currentUserId,
        isLeave: isSelfLeave,
      });
    }

    res.json({ 
      message: isSelfLeave ? 'Left group successfully' : 'Member removed successfully' 
    });
  })
);

/**
 * DELETE /groups/:id
 * Delete a group (admin only)
 */
router.delete(
  '/groups/:id',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const userId = req.user!.userId;

    if (isNaN(groupId)) {
      res.status(400).json({ error: 'Invalid group ID' });
      return;
    }

    // Check if user is an admin
    const membership = await prisma.groupMembership.findFirst({
      where: { groupId, userId, role: 'ADMIN' },
    });

    if (!membership) {
      res.status(403).json({ error: 'Admin access required' });
      return;
    }

    // Delete group and all related data in transaction
    await prisma.$transaction(async (tx: { message: { deleteMany: (arg0: { where: { groupId: number; }; }) => any; }; groupMembership: { deleteMany: (arg0: { where: { groupId: number; }; }) => any; }; group: { delete: (arg0: { where: { id: number; }; }) => any; }; }) => {
      // Delete all messages
      await tx.message.deleteMany({
        where: { groupId },
      });

      // Delete all memberships
      await tx.groupMembership.deleteMany({
        where: { groupId },
      });

      // Delete the group
      await tx.group.delete({
        where: { id: groupId },
      });
    });

    // Emit WebSocket event
    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('groupDeleted', {
        groupId,
        deletedBy: userId,
      });
    }

    res.json({ message: 'Group deleted successfully' });
  })
);

/**
 * POST /groups/:id/join
 * Join a public group
 */
router.post(
  '/groups/:id/join',
  authenticateToken,
  asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
    const groupId = parseInt(req.params.id, 10);
    const userId = req.user!.userId;

    if (isNaN(groupId)) {
      res.status(400).json({ error: 'Invalid group ID' });
      return;
    }

    // Check if group exists and is public
    const group = await prisma.group.findUnique({
      where: { id: groupId },
      select: { id: true, name: true, isPrivate: true }
    });

    if (!group) {
      res.status(404).json({ error: 'Group not found' });
      return;
    }

    if (group.isPrivate) {
      res.status(403).json({ error: 'Cannot join private group' });
      return;
    }

    // Check if already a member
    const existingMembership = await prisma.groupMembership.findFirst({
      where: { groupId, userId },
    });

    if (existingMembership) {
      res.status(409).json({ error: 'Already a member' });
      return;
    }

    const membership = await prisma.groupMembership.create({
      data: {
        groupId,
        userId,
        role: 'MEMBER',
      },
    });

    // Emit WebSocket event
    if (req.app.get('io')) {
      const io = req.app.get('io');
      io.to(`group_${groupId}`).emit('memberJoined', {
        groupId,
        userId,
        joinedAt: membership.joinedAt,
      });
    }

    res.status(201).json({
      message: 'Joined group successfully',
      groupId,
      role: 'MEMBER',
      joinedAt: membership.joinedAt,
    });
  })
);

export default router;