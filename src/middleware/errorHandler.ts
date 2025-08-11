import { Request, Response, NextFunction } from 'express';

export function errorHandler(err: any, req: Request, res: Response, next: NextFunction) {
  console.error(`[${req.method} ${req.originalUrl}]`, err);

  if (res.headersSent) return next(err);

  // Default values
  const status = typeof err.status === 'number' ? err.status : 500;
  const code = err.code || undefined; // e.g. for database errors
  const message =
    typeof err.message === 'string'
      ? err.message
      : status === 404
        ? 'Not Found'
        : 'Internal Server Error';

  const response: Record<string, any> = { error: message };
  if (process.env.NODE_ENV === 'development' && err.stack) {
    response.stack = err.stack;
  }
  if (code) {
    response.code = code;
  }
  if (err.errors) {
    response.errors = err.errors;
  } else if (err.details) {
    response.details = err.details;
  }

  res.status(status).json(response);
}