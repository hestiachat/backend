import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import { Server as SocketIOServer } from 'socket.io';

import authRoutes from './routes/auth';
import groupRoutes from './routes/groups';
import { authenticateToken } from './middleware/auth';
import { errorHandler } from './middleware/errorHandler';
import { setupSocket } from './socket';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: "*" },
});

app.use(cors());
app.use(express.json());

app.use(authRoutes);
app.use(groupRoutes);

app.use(errorHandler);

setupSocket(io);

const PORT = parseInt(process.env.PORT || '4000');

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});
