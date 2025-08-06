import request from 'supertest';
import express from 'express';
import authRoutes from '../src/routes/auth';

// Mock Prisma client
jest.mock('../src/prismaClient', () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      create: jest.fn(),
    },
  },
}));

// Mock bcrypt
jest.mock('bcrypt', () => ({
  hash: jest.fn(),
  compare: jest.fn(),
}));

// Mock jsonwebtoken
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mock_jwt_token'),
}));

import { prisma } from '../src/prismaClient';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());
app.use('/api', authRoutes);

describe('Auth Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /api/register', () => {
    it('should register a new user successfully', async () => {
      const mockUser = { id: 1, username: 'testuser' };
      
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
      (prisma.user.create as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed_password');

      const response = await request(app)
        .post('/api/register')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        id: 1,
        username: 'testuser'
      });
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { username: 'testuser' }
      });
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 10);
      expect(prisma.user.create).toHaveBeenCalledWith({
        data: { username: 'testuser', password: 'hashed_password' }
      });
    });

    it('should return error for invalid username', async () => {
      const response = await request(app)
        .post('/api/register')
        .send({
          username: 'ab', // Too short
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('username');
    });

    it('should return error for invalid password', async () => {
      const response = await request(app)
        .post('/api/register')
        .send({
          username: 'testuser',
          password: '123' // Too short
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('password');
    });

    it('should return error if user already exists', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({ id: 1, username: 'testuser' });

      const response = await request(app)
        .post('/api/register')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('User already exists');
    });
  });

  describe('POST /api/login', () => {
    it('should login user successfully with valid credentials', async () => {
      const mockUser = { id: 1, username: 'testuser', password: 'hashed_password' };
      
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/api/login')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        token: 'mock_jwt_token'
      });
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { username: 'testuser' }
      });
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashed_password');
      expect(jwt.sign).toHaveBeenCalledWith(
        { userId: 1, username: 'testuser' },
        expect.any(String),
        { expiresIn: '1d' }
      );
    });

    it('should return error for non-existent user', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      const response = await request(app)
        .post('/api/login')
        .send({
          username: 'nonexistent',
          password: 'password123'
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should return error for invalid password', async () => {
      const mockUser = { id: 1, username: 'testuser', password: 'hashed_password' };
      
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const response = await request(app)
        .post('/api/login')
        .send({
          username: 'testuser',
          password: 'wrongpassword'
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid credentials');
    });

    it('should return error for invalid input format', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({
          username: 'ab', // Too short
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('username');
    });
  });
});