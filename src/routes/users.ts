import express, { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import jwt from 'jsonwebtoken';

const router = express.Router();

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req: Request, res: Response, next: Function) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.substring(7)
    : null;
  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!);
    // @ts-ignore
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
    return;
  }
};

// --- HELPERS ---
const allowedExt = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const ensureDir = (dir: string) => fs.mkdirSync(dir, { recursive: true });
const isHttpUrl = (value: string) => /^https?:\/\//i.test(value);
const toPublicUrl = (req: Request, maybeRelativeUrl?: string | null) => {
  if (!maybeRelativeUrl) return null;
  if (isHttpUrl(maybeRelativeUrl)) return maybeRelativeUrl;
  const rel = maybeRelativeUrl.startsWith('/') ? maybeRelativeUrl : `/${maybeRelativeUrl}`;
  return `${req.protocol}://${req.get('host')}${rel}`;
};

// --- MULTER SETUP (AVATARS) ---
const avatarStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.resolve(__dirname, '../../uploads/avatars');
    ensureDir(uploadPath);
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `avatar-${unique}${ext}`);
  }
});
const uploadAvatar = multer({
  storage: avatarStorage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!file.mimetype.startsWith('image/') || !allowedExt.includes(ext)) {
      return cb(new Error('Only image files are allowed!'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// --- MULTER SETUP (BANNERS) ---
const bannerStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.resolve(__dirname, '../../uploads/banners');
    ensureDir(uploadPath);
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `banner-${unique}${ext}`);
  }
});
const uploadBanner = multer({
  storage: bannerStorage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!file.mimetype.startsWith('image/') || !allowedExt.includes(ext)) {
      return cb(new Error('Only image files are allowed!'));
    }
    cb(null, true);
  },
  limits: { fileSize: 8 * 1024 * 1024 } // 8MB for banners
});

// --- ROUTES ---

// GET /users/by-username/:username
router.get('/by-username/:username', asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const username = req.params.username;
  if (!username || typeof username !== 'string') {
    res.status(400).json({ error: 'Invalid username' });
    return;
  }
  const user = await prisma.user.findUnique({
    where: { username },
    select: { id: true, username: true, profilePictureUrl: true, bio: true, createdAt: true, profileBannerUrl: true}
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({
    ...user,
    profilePictureUrl: user.profilePictureUrl ? toPublicUrl(req, user.profilePictureUrl) : null,
    profileBannerUrl: user.profileBannerUrl ? toPublicUrl(req, user.profileBannerUrl) : null,
    createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
  });
}));

// PATCH /users/bio
router.patch('/bio', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  // @ts-ignore
  const userId = req.user?.userId;
  const { bio } = req.body;
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  if (typeof bio !== 'string' || bio.length > 500) {
    res.status(400).json({ error: 'Bio must be a string up to 500 characters.' });
    return;
  }
  const user = await prisma.user.update({
    where: { id: userId },
    data: { bio },
    select: { id: true, username: true, profilePictureUrl: true, bio: true, createdAt: true, profileBannerUrl: true}
  });
  res.json({
    ...user,
    profilePictureUrl: user.profilePictureUrl ? toPublicUrl(req, user.profilePictureUrl) : null,
    profileBannerUrl: user.profileBannerUrl ? toPublicUrl(req, user.profileBannerUrl) : null,
    createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
  });
}));

// GET /users/by-id/:id
router.get('/by-id/:id', asyncHandler(async (req: Request, res: Response): Promise<void> => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    res.status(400).json({ error: 'Invalid user ID' });
    return;
  }
  const user = await prisma.user.findUnique({
    where: { id },
    select: { id: true, username: true, profilePictureUrl: true, bio: true, createdAt: true, profileBannerUrl: true}
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({
    ...user,
    profilePictureUrl: user.profilePictureUrl ? toPublicUrl(req, user.profilePictureUrl) : null,
    profileBannerUrl: user.profileBannerUrl ? toPublicUrl(req, user.profileBannerUrl) : null,
    createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
  });
}));

// PATCH /users/username
router.patch('/username', authenticateToken, asyncHandler(async (req: Request, res: Response): Promise<void> => {
  // @ts-ignore
  const userId = req.user?.userId;
  const { username } = req.body;
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  if (!username || typeof username !== 'string') {
    res.status(400).json({ error: 'username is required' });
    return;
  }
  try {
    const user = await prisma.user.update({
      where: { id: userId },
      data: { username },
      select: { id: true, username: true, profilePictureUrl: true, createdAt: true, profileBannerUrl: true},
    });
    res.json({
      ...user,
      profilePictureUrl: user.profilePictureUrl ? toPublicUrl(req, user.profilePictureUrl) : null,
      profileBannerUrl: user.profileBannerUrl ? toPublicUrl(req, user.profileBannerUrl) : null,
      createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
    });
  } catch (err: any) {
    if (err.code === 'P2002') {
      res.status(409).json({ error: 'Username already taken' });
      return;
    } else {
      throw err;
    }
  }
}));

// DELETE /users/me
router.delete('/me', authenticateToken, asyncHandler(async (req: Request, res: Response): Promise<void> => {
  // @ts-ignore
  const userId = req.user?.userId;
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  await prisma.user.delete({ where: { id: userId } });
  res.status(204).send();
}));

// GET /users/me
router.get('/me', authenticateToken, asyncHandler(async (req: Request, res: Response): Promise<void> => {
  // @ts-ignore
  const userId = req.user?.userId;
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, username: true, profilePictureUrl: true, createdAt: true, profileBannerUrl: true}
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({
    ...user,
    profilePictureUrl: user.profilePictureUrl ? toPublicUrl(req, user.profilePictureUrl) : null,
    profileBannerUrl: user.profileBannerUrl ? toPublicUrl(req, user.profileBannerUrl) : null,
    createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
  });
}));

// PATCH /users/profile-picture
router.patch('/profile-picture', authenticateToken, uploadAvatar.single('avatar'), asyncHandler(async (req: Request, res: Response): Promise<void> => {
  // @ts-ignore
  const userId = req.user?.userId;
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  let profilePictureUrl: string | undefined = undefined;

  if (req.file) {
    profilePictureUrl = `/uploads/avatars/${req.file.filename}`;
  } else if (typeof req.body.profilePictureUrl === 'string' && req.body.profilePictureUrl.trim() !== '') {
    profilePictureUrl = req.body.profilePictureUrl.trim();
  }

  if (!profilePictureUrl) {
    res.status(400).json({ error: 'profilePictureUrl or avatar file is required' });
    return;
  }

  try {
    const user = await prisma.user.update({
      where: { id: userId },
      data: { profilePictureUrl },
      select: { id: true, username: true, profilePictureUrl: true, createdAt: true, profileBannerUrl: true},
    });

    const returnedProfilePictureUrl = toPublicUrl(req, user.profilePictureUrl);

    res.json({
      ...user,
      profilePictureUrl: returnedProfilePictureUrl,
      profileBannerUrl: user.profileBannerUrl ? toPublicUrl(req, user.profileBannerUrl) : null,
      createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
    });
  } catch (e) {
    if (req.file) {
      fs.unlink(path.join(req.file.destination, req.file.filename), () => {});
    }
    throw e;
  }
}));

// PATCH /users/profile-banner
router.patch('/profile-banner', authenticateToken, uploadBanner.single('banner'), asyncHandler(async (req: Request, res: Response): Promise<void> => {
  // @ts-ignore
  const userId = req.user?.userId;
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  let profileBannerUrl: string | undefined = undefined;

  if (req.file) {
    // Save relative path to the uploaded banner
    profileBannerUrl = `/uploads/banners/${req.file.filename}`;
  } else if (typeof req.body.profileBannerUrl === 'string' && req.body.profileBannerUrl.trim() !== '') {
    // Allow setting an external URL as banner
    profileBannerUrl = req.body.profileBannerUrl.trim();
  }

  if (!profileBannerUrl) {
    res.status(400).json({ error: 'profileBannerUrl or banner file is required' });
    return;
  }

  if (typeof profileBannerUrl === 'string' && profileBannerUrl.length > 2048) {
    res.status(400).json({ error: 'profileBannerUrl is too long (max 2048 chars)' });
    return;
  }

  try {
    const user = await prisma.user.update({
      where: { id: userId },
      data: { profileBannerUrl },
      select: { id: true, username: true, profileBannerUrl: true, createdAt: true, profilePictureUrl: true},
    });

    const returnedProfileBannerUrl = toPublicUrl(req, user.profileBannerUrl);

    res.json({
      ...user,
      profileBannerUrl: returnedProfileBannerUrl,
      profilePictureUrl: user.profilePictureUrl ? toPublicUrl(req, user.profilePictureUrl) : null,
      createdAt: new Date(user.createdAt).getTime(), // Unix timestamp
    });
  } catch (e) {
    if (req.file) {
      fs.unlink(path.join(req.file.destination, req.file.filename), () => {});
    }
    throw e;
  }
}));

export default router;