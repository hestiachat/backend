import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { Server as SocketIOServer } from 'socket.io';
import publicAPILimiter from './middleware/ratelimit'

import messageRoutes from './routes/messages';
import authRoutes from './routes/auth';
import usersRoutes from './routes/users';
import friendsRoutes from './routes/friends';
import groupRoutes from './routes/groups';
import { errorHandler } from './middleware/errorHandler';
import { setupSocket } from './socket';

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { 
    origin: "*",  // Allow all origins
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: false  // Set to false for open access
  },
});

// Disable helmet for maximum compatibility
// app.use(helmet());

app.use(compression());

// Allow all origins with no restrictions
app.use(cors({
  origin: "*",  // Allow all origins
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: false  // Disable credentials for public API
}));

// Add manual CORS headers for extra compatibility
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.json());

// Add health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// app.use(publicAPILimiter);

// Routes (with or without /api prefix)
app.use('/api', authRoutes);
app.use('/api', groupRoutes);
app.use('/api', messageRoutes);
app.use('/api', usersRoutes);
app.use('/api', friendsRoutes);

// Also serve routes without /api prefix for flexibility
app.use('/', authRoutes);
app.use('/', groupRoutes);
app.use('/', messageRoutes);
app.use('/', usersRoutes);
app.use('/', friendsRoutes);

app.use(errorHandler);

setupSocket(io);
app.set('io', io);

const PORT = parseInt(process.env.PORT || '4000');

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  console.log(`API available at http://0.0.0.0:${PORT}/api`);
});