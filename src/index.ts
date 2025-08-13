import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import http from 'http';
import path from 'path';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { Server as SocketIOServer } from 'socket.io';
import publicAPILimiter from './middleware/ratelimit'

import authRoutes from './routes/auth';
import usersRoutes from './routes/users';
import friendsRoutes from './routes/friends';
import groupRoutes from './routes/groups';
import rootRoutes from './routes/root';
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
app.use(cors({ origin: '*' }));

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
app.use('/', rootRoutes);
app.use('/auth', authRoutes);
app.use('/groups', groupRoutes);
app.use('/users', usersRoutes);
app.use('/friends', friendsRoutes);

app.use(errorHandler);

app.use('/uploads/avatars', express.static(path.join(__dirname, '../uploads/avatars')));
setupSocket(io);
app.set('io', io);

const PORT = parseInt(process.env.PORT || '4000');

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  console.log(`working dir: ${path.resolve(__dirname)}`);
});