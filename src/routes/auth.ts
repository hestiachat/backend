import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import rateLimit from 'express-rate-limit';
import { prisma } from '../prismaClient';
import { z } from 'zod';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET!;

interface AuthBody {
  username: string;
  password: string;
}

// Walidacja wejściowa
const authSchema = z.object({
  username: z.string().min(3).max(32),
  password: z.string().min(6).max(128)
});

// Rate limiters
const registerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many registration attempts, try again later.' },
});

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, try again later.' },
});

router.post('/register', registerLimiter, asyncHandler(async (req: Request<{}, {}, AuthBody>, res: Response) => {
  const parse = authSchema.safeParse(req.body);
  if (!parse.success) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }
  const { username, password } = parse.data;

  const existingUser = await prisma.user.findUnique({ where: { username } });
  if (existingUser) {
    res.status(400).json({ error: 'User already exists' });
    return;
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { username, password: hashed },
  });

  res.json({ id: user.id, username: user.username });
}));

router.post('/login', loginLimiter, asyncHandler(async (req: Request<{}, {}, AuthBody>, res: Response) => {
  const parse = authSchema.safeParse(req.body);
  if (!parse.success) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }
  const { username, password } = parse.data;

  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '1d' }
  );

  res.json({ token });
}));

export default router;