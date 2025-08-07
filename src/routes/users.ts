import express from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';

const router = express.Router();

/**
 * GET /users/by-username/:username
 * Returns: { id, username } or 404
 */
router.get('/users/by-username/:username', asyncHandler(async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { username: req.params.username },
    select: { id: true, username: true },
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json(user);
}));

export default router;