// src/types/express.d.ts

import { UserPayload } from '../middleware/auth'; // adjust path to match your project

declare global {
  namespace Express {
    interface Request {
      user?: UserPayload; // <-- Add your custom user type here
    }
  }
}
