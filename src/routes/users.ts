import express, { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { prisma } from '../prismaClient';
import authenticateToken from './auth';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

const router = express.Router();

// Allowed image extensions
const allowedExt = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];

// Multer setup for avatar uploads
const avatarStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, '../../uploads/avatars');
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Save file as user-<userId>-timestamp.ext
    const ext = path.extname(file.originalname).toLowerCase();
    const userId = req.user?.userId || 'unknown';
    cb(null, `user-${userId}-${Date.now()}${ext}`);
  }
});
const upload = multer({
  storage: avatarStorage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!file.mimetype.startsWith('image/') || !allowedExt.includes(ext)) {
      return cb(new Error('Only image files are allowed!'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});


/**
 * GET /users/by-id/:id
 * Returns: { id, username, profilePictureUrl } or 404
 */
router.get('/by-id/:id', asyncHandler(async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  if (isNaN(id)) {
    res.status(400).json({ error: 'Invalid user ID' });
    return;
  }
  const user = await prisma.user.findUnique({
    where: { id },
    select: { id: true, username: true, profilePictureUrl: true }
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json(user);
}));

/**
 * PATCH /users/username
 * Body: { username: string }
 * Requires authentication.
 */
router.patch('/username', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const { username } = req.body;
  if (!username || typeof username !== 'string') {
    res.status(400).json({ error: 'username is required' });
    return;
  }
  try {
    const user = await prisma.user.update({
      where: { id: userId },
      data: { username },
      select: { id: true, username: true, profilePictureUrl: true },
    });
    res.json(user);
  } catch (err: any) {
    if (err.code === 'P2002') { // Prisma unique constraint failed
      res.status(409).json({ error: 'Username already taken' });
    } else {
      throw err;
    }
  }
}));

/**
 * DELETE /users/me
 * Requires authentication. Deletes the current user.
 */
router.delete('/me', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  await prisma.user.delete({
    where: { id: userId }
  });
  res.status(204).send();
}));

/**
 * GET /users/me
 * Requires authentication. Returns: { id, username, profilePictureUrl }
 */
router.get('/me', authenticateToken, asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, username: true, profilePictureUrl: true }
  });
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json(user);
}));

/**
 * PATCH /users/profile-picture
 * Supports either a profilePictureUrl string or an avatar file upload.
 */
router.patch(
  '/profile-picture',
  authenticateToken,
  upload.single('avatar'),
  asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.userId;
    let profilePictureUrl: string | undefined = undefined;

    if (req.file) {
      // If file uploaded, use its path
      profilePictureUrl = `/uploads/avatars/${req.file.filename}`;
    } else if (typeof req.body.profilePictureUrl === 'string') {
      // Fallback: if URL string provided
      profilePictureUrl = req.body.profilePictureUrl;
    }

    if (!profilePictureUrl) {
      res.status(400).json({ error: 'profilePictureUrl or avatar file is required' });
      return;
    }

    try {
      const user = await prisma.user.update({
        where: { id: userId },
        data: { profilePictureUrl },
        select: { id: true, username: true, profilePictureUrl: true },
      });
      res.json(user);
    } catch (e) {
      // Clean up uploaded file if DB update fails
      if (req.file) {
        fs.unlink(path.join(req.file.destination, req.file.filename), () => {});
      }
      throw e;
    }
  })
);

export default router;