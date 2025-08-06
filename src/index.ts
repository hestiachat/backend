import dotenv from 'dotenv';

// Load environment variables first
dotenv.config();

import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { Server as SocketIOServer } from 'socket.io';

import authRoutes from './routes/auth';
import groupRoutes from './routes/groups';
import { authenticateToken } from './middleware/auth';
import { errorHandler } from './middleware/errorHandler';
import { setupSocket } from './socket';

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: "*" },
});

// Security middleware
app.use(helmet());

// Performance middleware
app.use(compression());

// CORS middleware
app.use(cors());

// Body parsing middleware
app.use(express.json());

// Routes
app.use('/api', authRoutes);
app.use('/api', groupRoutes);

// Error handling middleware (must be last)
app.use(errorHandler);

setupSocket(io);

const PORT = parseInt(process.env.PORT || '4000');

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
