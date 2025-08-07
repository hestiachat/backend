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

interface JwtPayload {
  userId: number;
  username: string;
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

const authStatusLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many auth status requests, try again later.' },
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

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '1d' }
  );

  res.json({ 
    token,
    user: { id: user.id, username: user.username }
  });
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

  res.json({ 
    token,
    user: { id: user.id, username: user.username }
  });
}));

// Auth status endpoint
router.get('/auth-status', authStatusLimiter, asyncHandler(async (req: Request, res: Response) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ 
        error: 'No token provided',
        authenticated: false 
      });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    
    // Optional: Verify user still exists in database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, username: true }
    });

    if (!user) {
      res.status(401).json({ 
        error: 'User not found',
        authenticated: false 
      });
      return;
    }

    // Token is valid and user exists
    res.status(200).json({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
      }
    });

  } catch (error) {
    // Token is invalid, expired, or malformed
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({ 
        error: 'Invalid token',
        authenticated: false 
      });
    } else if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({ 
        error: 'Token expired',
        authenticated: false 
      });
    } else {
      console.error('Auth status error:', error);
      res.status(401).json({ 
        error: 'Authentication failed',
        authenticated: false 
      });
    }
  }
}));

export default router;