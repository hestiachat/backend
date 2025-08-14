import express from "express";
import http from "http";
import cors from "cors";
import compression from "compression";
import { Server as SocketIOServer } from "socket.io";
import publicAPILimiter from "./middleware/ratelimit";
import authRoutes from "./routes/auth";
import usersRoutes from "./routes/users";
import friendsRoutes from "./routes/friends";
import groupRoutes from "./routes/groups";
import rootRoutes from "./routes/root";
import { errorHandler } from "./middleware/errorHandler";
import { setupSocket } from "./socket";
import { prisma } from "./prismaClient";
import path from "path";


const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: false,
  },
});

// Disable helmet for maximum compatibility
// app.use(helmet());

app.use(compression());
app.use(cors({ origin: "*" }));

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Methods",
    "GET,PUT,POST,DELETE,OPTIONS"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Content-Length, X-Requested-With"
  );

  if (req.method === "OPTIONS") {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.json());

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// app.use(publicAPILimiter);
app.use("/", rootRoutes);
app.use("/auth", authRoutes);
app.use("/groups", groupRoutes);
app.use("/users", usersRoutes);
app.use("/friends", friendsRoutes);

app.use(errorHandler);

// Use Bun's import.meta.dir for static files
// const __dirname = path.dirname(import.meta.path);
const __dirname = path.dirname(import.meta.path)
const avatarsDir = path.join(__dirname, "../uploads/avatars");
app.use("/uploads/avatars", express.static(avatarsDir));

setupSocket(io);
app.set("io", io);

const PORT = parseInt(process.env.PORT || "4000");

// Use setInterval instead of node-cron
setInterval(async () => {
  const twoMinutesAgo = new Date(Date.now() - 1 * 60 * 1000);
  await prisma.user.updateMany({
    where: {
      lastActive: { lt: twoMinutesAgo },
      status: "active",
    },
    data: { status: "offline" },
  });
}, 60 * 1000); // Every minute

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  console.log(`working dir: ${import.meta.dirname}`);
});