import express from 'express';
import asyncHandler from 'express-async-handler';
import Joi from 'joi';
import { prisma } from '../prismaClient';
import { authenticateToken, AuthenticatedRequest } from '../middleware/auth';

const router = express.Router();

// Validation schemas
const createGroupSchema = Joi.object({
  name: Joi.string().min(1).max(100).required()
});

/**
 * POST /groups
 * Tworzy nową grupę. Wymaga autoryzacji.
 * Body: { name: string }
 */
router.post('/groups', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res) => {
  // Validate input
  const { error, value } = createGroupSchema.validate(req.body);
  if (error) {
    res.status(400).json({ error: error.details[0].message });
    return;
  }

  const { name } = value;

  try {
    const group = await prisma.group.create({ data: { name } });
    await prisma.groupMembership.create({
      data: { groupId: group.id, userId: req.user!.userId }
    });
    res.json(group);
  } catch {
    res.status(400).json({ error: 'Group name taken or invalid data' });
  }
}));


/**
 * GET /groups
 * Zwraca wszystkie grupy, do których należy użytkownik. Wymaga autoryzacji.
 */
router.get('/groups', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res) => {
  const groups = await prisma.group.findMany({
    where: {
      memberships: {
        some: { userId: req.user!.userId }
      }
    }
  });
  res.json(groups);
}));

/**
 * GET /groups/:id/messages
 * Zwraca wiadomości z grupy. Wymaga autoryzacji.
 */
router.get('/groups/:id/messages', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res) => {
  const groupId = parseInt(req.params.id);
  const messages = await prisma.message.findMany({
    where: { groupId },
    include: { user: { select: { username: true } } },
    orderBy: { createdAt: 'asc' },
  });

  res.json(messages);
}));

export default router;