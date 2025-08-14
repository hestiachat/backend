import { Server, Socket } from "socket.io";
import { prisma } from "./prismaClient";
import { encryptMessage, decryptMessage } from "./cryptoUtils";
import { authenticateSocket } from "./socketAuth";

// --- Helper Functions ---

async function setUserStatus(userId: number, status: "active" | "offline") {
  try {
    await prisma.user.update({
      where: { id: userId },
      data: { status, lastActive: status === "active" ? new Date() : undefined }
    });
  } catch (err) {
    console.error(`Failed to set user ${userId} status to ${status}:`, err);
  }
}

function joinRoom(socket: Socket, room: string) {
  if (!socket.rooms.has(room)) socket.join(room);
}

// --- Event Handlers ---

async function handleSendDM(io: Server, socket: Socket, userId: number, { toId, content }: any) {
  if (!content || !toId || userId === toId) {
    socket.emit("error", { error: "Invalid DM parameters" });
    return;
  }
  try {
    const friendship = await prisma.friend.findFirst({
      where: {
        OR: [
          { userId, friendId: toId },
          { userId: toId, friendId: userId }
        ]
      }
    });
    if (!friendship) {
      socket.emit("error", { error: "You can only DM friends" });
      return;
    }
    const recipient = await prisma.user.findUnique({ where: { id: toId } });
    if (!recipient) {
      socket.emit("error", { error: "Recipient not found" });
      return;
    }
    const encryptedData = encryptMessage(content.trim());
    const message = await prisma.message.create({
      data: {
        content: encryptedData.encrypted,
        iv: encryptedData.iv,
        authTag: encryptedData.authTag,
        userId,
        recipientId: toId
      },
      include: { user: { select: { username: true } } },
    });
    const roomName = `dm_${Math.min(userId, toId)}_${Math.max(userId, toId)}`;
    joinRoom(socket, roomName);
    const messageData = {
      id: message.id,
      content: content.trim(),
      createdAt: message.createdAt.getTime(),
      userId: message.userId,
      username: message.user.username,
      recipientId: toId,
    };
    io.to(roomName).emit("newDM", messageData);
    io.to(`user_${toId}`).emit("dmNotification", {
      ...messageData,
      senderId: userId,
      senderUsername: message.user.username,
    });
  } catch (err) {
    socket.emit("error", { error: "Failed to send DM" });
    console.error(err);
  }
}

async function handleGetDMHistory(socket: Socket, userId: number, { otherId }: any, cb: Function) {
  if (!otherId || userId === otherId) {
    cb({ error: "Invalid user ID" });
    return;
  }
  try {
    const friendship = await prisma.friend.findFirst({
      where: {
        OR: [
          { userId, friendId: otherId },
          { userId: otherId, friendId: userId }
        ]
      }
    });
    if (!friendship) {
      cb({ error: "You can only view messages with friends" });
      return;
    }
    const messages = await prisma.message.findMany({
      where: {
        AND: [
          { groupId: null },
          {
            OR: [
              { userId, recipientId: otherId },
              { userId: otherId, recipientId: userId }
            ]
          }
        ]
      },
      orderBy: { createdAt: 'asc' },
      include: { user: { select: { username: true } } }
    });

    const decryptedMessages = messages.map((msg) => ({
      id: msg.id,
      content:
        msg.iv && msg.authTag
          ? decryptMessage({ encrypted: msg.content, iv: msg.iv, authTag: msg.authTag })
          : '[Encrypted]',
      createdAt: msg.createdAt.getTime(),
      userId: msg.userId,
      username: msg.user.username
    }));
    cb(decryptedMessages);
  } catch (err) {
    cb({ error: "Failed to get DM history" });
    console.error(err);
  }
}

async function handleJoinGroup(
  socket: Socket,
  userId: number,
  data?: { groupId?: number }
) {
  const { groupId } = data || {};
  if (!groupId) return;
  try {
    const membership = await prisma.groupMembership.findFirst({ where: { groupId, userId } });
    if (membership) socket.join(`group_${groupId}`);
  } catch (err) {
    socket.emit("error", { error: "Failed to join group" });
    console.error(err);
  }
}

async function handleSendGroupMessage(io: Server, socket: Socket, userId: number, { groupId, content }: any) {
  if (!content || !groupId) {
    socket.emit("error", { error: "Invalid group message parameters" });
    return;
  }
  try {
    const isMember = await prisma.groupMembership.findFirst({
      where: { groupId, userId }
    });
    if (!isMember) {
      socket.emit("error", { error: "Not a group member" });
      return;
    }
    const encryptedData = encryptMessage(content.trim());
    const message = await prisma.message.create({
      data: {
        content: encryptedData.encrypted,
        iv: encryptedData.iv,
        authTag: encryptedData.authTag,
        userId,
        groupId
      },
      include: { user: { select: { username: true } } }
    });
    joinRoom(socket, `group_${groupId}`);
    const messageData = {
      id: message.id,
      content: content.trim(),
      createdAt: message.createdAt.getTime(),
      userId: message.userId,
      username: message.user.username,
      groupId
    };
    io.to(`group_${groupId}`).emit("newGroupMessage", messageData);
  } catch (err) {
    socket.emit("error", { error: "Failed to send group message" });
    console.error(err);
  }
}

async function handleGetGroupHistory(socket: Socket, userId: number, { groupId }: any, cb: Function) {
  if (!groupId) {
    cb({ error: "Invalid group ID" });
    return;
  }
  try {
    const isMember = await prisma.groupMembership.findFirst({
      where: { groupId, userId }
    });
    if (!isMember) {
      cb({ error: "Not a group member" });
      return;
    }
    const messages = await prisma.message.findMany({
      where: { groupId },
      orderBy: { createdAt: 'asc' },
      include: { user: { select: { username: true } } }
    });
    const decryptedMessages = messages.map((msg) => ({
      id: msg.id,
      content:
        msg.iv && msg.authTag
          ? decryptMessage({ encrypted: msg.content, iv: msg.iv, authTag: msg.authTag })
          : '[Encrypted]',
      createdAt: msg.createdAt.getTime(),
      userId: msg.userId,
      username: msg.user.username,
      groupId: msg.groupId
    }));
    cb(decryptedMessages);
  } catch (err) {
    cb({ error: "Failed to get group history" });
    console.error(err);
  }
}

// --- Main Setup ---

export function setupSocket(io: Server) {
  io.on("connection", (socket) => {
    const userId = authenticateSocket(socket);
    if (!userId) {
      socket.emit("error", { error: "Authentication failed" });
      socket.disconnect();
      return;
    }
    socket.join(`user_${userId}`);
    setUserStatus(userId, "active");

    socket.on("disconnect", () => setUserStatus(userId, "offline"));
    socket.on("sendDM", (data) => handleSendDM(io, socket, userId, data));
    socket.on("getDMHistory", (data, cb) => handleGetDMHistory(socket, userId, data, cb));
    socket.on("joinGroup", (data) => handleJoinGroup(socket, userId, data));
    socket.on("sendGroupMessage", (data) => handleSendGroupMessage(io, socket, userId, data));
    socket.on("getGroupHistory", (data, cb) => handleGetGroupHistory(socket, userId, data, cb));
  });
}