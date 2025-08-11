import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import express, { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_EXPIRES_IN = '7d';

interface JwtPayload {
  userId: number;
  username: string;
}

// REGISTER
router.post('/register', asyncHandler(async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }

  if (username.length < 3 || username.length > 32) {
    res.status(400).json({ error: 'Username must be from 3 to 32 characters.' });
    return;
  }

  if (password.length < 8 || password.length > 128) {
    res.status(400).json({ error: 'Password must be from 8 to 128 characters.' });
    return;
  }

  const existingUser = await prisma.user.findUnique({ where: { username } });
  if (existingUser) {
    res.status(409).json({ error: 'Username already taken.' });
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      username,
      password: hashedPassword,
    },
  });

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.status(201).json({
    message: 'User registered successfully.',
    user: { id: user.id, username: user.username },
    token,
  });
}));

// LOGIN
router.post('/login', asyncHandler(async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: 'Username and password are required.' });
    return;
  }

  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) {
    res.status(401).json({ error: 'Invalid credentials.' });
    return;
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    res.status(401).json({ error: 'Invalid credentials.' });
    return;
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );

  res.status(200).json({
    message: 'Login successful.',
    user: { id: user.id, username: user.username },
    token,
  });
}));

// AUTH STATUS
router.get('/status', asyncHandler(async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'No token provided', authenticated: false });
      return;
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, username: true }
    });

    if (!user) {
      res.status(401).json({ error: 'User not found', authenticated: false });
      return;
    }

    res.status(200).json({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
      }
    });

  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({ error: 'Invalid token', authenticated: false });
    } else if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({ error: 'Token expired', authenticated: false });
    } else {
      console.error('Auth status error:', error);
      res.status(401).json({ error: 'Authentication failed', authenticated: false });
    }
  }
}));

export default router;
