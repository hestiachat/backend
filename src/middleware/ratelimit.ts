import rateLimit from 'express-rate-limit';

// Public API rate limiter
const publicAPILimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Adjust as needed
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true, // Send RateLimit-* headers
  legacyHeaders: false,  // Disable X-RateLimit-* headers
  keyGenerator: (req): string => {
    const xfwd = req.headers['x-forwarded-for'];
    if (typeof xfwd === 'string') return xfwd;
    if (Array.isArray(xfwd)) return xfwd[0];
    return req.ip || '';
  },

  handler: (req, res, _next, options) => {
    const retryAfterSec = Math.ceil(options.windowMs / 1000);
    console.warn(
      `[RATE LIMIT] IP ${req.ip} exceeded ${options.max} requests in ${options.windowMs / 60000} minutes for ${req.originalUrl}`
    );
    res.status(options.statusCode || 429).json({
      error: 'Too many requests, please try again later.',
      limit: options.max,
      windowMinutes: options.windowMs / 60000,
      retryAfter: retryAfterSec,
    });
  },
});

export default publicAPILimiter;
