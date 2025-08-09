import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import express, { Request, Response, NextFunction } from 'express';
import asyncHandler from 'express-async-handler';
import rateLimit from 'express-rate-limit';
import { prisma } from '../prismaClient';
import fs from 'fs';
import path from 'path';

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET!;
const JWT_EXPIRES_IN = '7d';

interface JwtPayload {
  userId: number;
  username: string;
}

// Rate limits
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, try again later.' },
});

const logFilePath = path.resolve(__dirname, '../logs/ratelimits.json');

const logRateLimitEvent = (logEntry: object) => {
  const logData = JSON.stringify(logEntry) + '\n';
  fs.appendFile(logFilePath, logData, (err) => {
    if (err) {
      console.error('Failed to log rate-limit event:', err);
    }
  });
};

// Rate limiter
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  message: { error: 'Too many register attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => req.ip ?? 'unknown-ip',
  handler: (req: Request, res: Response, next: NextFunction, options) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      ip: req.ip ?? 'unknown-ip',
      method: req.method,
      path: req.originalUrl,
      message: options.message,
      statusCode: options.statusCode ?? 429,
    };

    // Log the rate-limit event to the file
    logRateLimitEvent(logEntry);

    // Log to console for debugging
    console.error(`Rate limit exceeded for IP: ${req.ip ?? 'unknown-ip'} at ${logEntry.timestamp}`);

    // Send the response
    res.status(logEntry.statusCode).send(logEntry.message);
  },
});


// REGISTER
router.post('/register', registerLimiter, asyncHandler(async (req: Request, res: Response) => {
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
router.post('/login', loginLimiter, asyncHandler(async (req: Request, res: Response) => {
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
const authStatusLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many auth status requests, try again later.' },
});

router.get('/status', authStatusLimiter, asyncHandler(async (req: Request, res: Response) => {
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