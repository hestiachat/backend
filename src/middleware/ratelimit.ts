import rateLimit from 'express-rate-limit';

// Add stronger rate limiting for public API
const publicAPILimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100000, // Limit each IP to 100, 000 requests per windowMs
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false,
});

export default publicAPILimiter;