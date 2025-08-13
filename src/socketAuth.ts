import jwt from "jsonwebtoken";
import { Socket } from "socket.io";

export function authenticateSocket(socket: Socket): number | null {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;
  if (!token) return null;
  try {
    const payload: any = jwt.verify(token, process.env.JWT_SECRET!);
    return payload.userId;
  } catch {
    return null;
  }
}