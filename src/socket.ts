import { Server } from "socket.io";
import { prisma } from "./prismaClient";
import crypto from "crypto";
import jwt from "jsonwebtoken"; // Assuming JWT is used for authentication

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

const getEncryptionKey = (): Buffer => {
  if (!ENCRYPTION_KEY) throw new Error('ENCRYPTION_KEY not set');
  if (ENCRYPTION_KEY.length !== 64) throw new Error('ENCRYPTION_KEY must be 64 chars (32 bytes hex)');
  return Buffer.from(ENCRYPTION_KEY, 'hex');
};

const encryptMessage = (text: string): { encrypted: string; iv: string; authTag: string } => {
  const iv = crypto.randomBytes(12);
  const key = getEncryptionKey();
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from('message', 'utf8'));
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
};

const decryptMessage = (encryptedData: { encrypted: string; iv: string; authTag: string }): string => {
  try {
    const key = getEncryptionKey();
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
    decipher.setAAD(Buffer.from('message', 'utf8'));
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return '[Message could not be decrypted]';
  }
};

// Utility to authenticate socket and get userId
function authenticateSocket(socket: any): number | null {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!token) return null;
  try {
    const payload: any = jwt.verify(token, process.env.JWT_SECRET!);
    return payload.userId;
  } catch {
    return null;
  }
}

export function setupSocket(io: Server) {
  io.on("connection", (socket) => {
    const userId = authenticateSocket(socket);
    if (!userId) {
      socket.emit("error", { error: "Authentication failed" });
      socket.disconnect();
      return;
    }
    socket.join(`user_${userId}`);

    // Join all DM and group rooms for this user (optional: on connect)
    // You may want to fetch user's groups and DM rooms and call socket.join for each.

    // DM send
    socket.on("sendDM", async ({ toId, content }) => {
      if (!content || !toId || userId === toId) {
        socket.emit("error", { error: "Invalid DM parameters" });
        return;
      }
      // Check friendship
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
      const recipient = await prisma.user.findUnique({ where: { id: toId }, select: { id: true, username: true } });
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
    });

    // DM history fetch
    socket.on("getDMHistory", async ({ otherId }, cb) => {
      if (!otherId || userId === otherId) {
        cb({ error: "Invalid user ID" });
        return;
      }
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

      const decryptedMessages = messages.map((msg) => {
        let decryptedContent = '[Encrypted]';
        if ('iv' in msg && 'authTag' in msg && msg.iv && msg.authTag) {
          decryptedContent = decryptMessage({
            encrypted: msg.content,
            iv: msg.iv,
            authTag: msg.authTag
          });
        }
        return {
          id: msg.id,
          content: decryptedContent,
          createdAt: msg.createdAt.getTime(),
          userId: msg.userId,
          username: msg.user.username
        };
      });
      cb(decryptedMessages);
    });

    // Join group room (client should call this after login)
    socket.on("joinGroup", async ({ groupId }) => {
      if (!groupId) return;
      const membership = await prisma.groupMembership.findFirst({
        where: { groupId, userId }
      });
      if (membership) {
        socket.join(`group_${groupId}`);
      }
    });

    // Send group message
    socket.on("sendGroupMessage", async ({ groupId, content }) => {
      if (!content || !groupId) {
        socket.emit("error", { error: "Invalid group message parameters" });
        return;
      }
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
      const messageData = {
        id: message.id,
        content: content.trim(),
        createdAt: message.createdAt.getTime(),
        userId: message.userId,
        username: message.user.username,
        groupId: groupId
      };
      io.to(`group_${groupId}`).emit("newGroupMessage", messageData);
    });

    // Get group messages
    socket.on("getGroupHistory", async ({ groupId }, cb) => {
      if (!groupId) {
        cb({ error: "Invalid group ID" });
        return;
      }
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
      const decryptedMessages = messages.map((msg) => {
        let decryptedContent = '[Encrypted]';
        if ('iv' in msg && 'authTag' in msg && msg.iv && msg.authTag) {
          decryptedContent = decryptMessage({
            encrypted: msg.content,
            iv: msg.iv,
            authTag: msg.authTag
          });
        }
        return {
          id: msg.id,
          content: decryptedContent,
          createdAt: msg.createdAt.getTime(),
          userId: msg.userId,
          username: msg.user.username,
          groupId: msg.groupId
        };
      });
      cb(decryptedMessages);
    });
  });
}