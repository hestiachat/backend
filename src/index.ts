import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { Server as SocketIOServer } from 'socket.io';

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
  cors: { origin: "*" },
});

app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json());

app.use(authRoutes);
app.use(groupRoutes);
app.use(messageRoutes);
app.use(usersRoutes);
app.use(friendsRoutes);

app.use(errorHandler);

setupSocket(io);
app.set('io', io);

const PORT = parseInt(process.env.PORT || '4000');

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});