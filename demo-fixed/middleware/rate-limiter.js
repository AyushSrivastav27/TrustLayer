/**
 * In-memory sliding-window rate limiter middleware for hardened reference app.
 * Defends sensitive authentication and checkout endpoints against automated abuse.
 */
export function rateLimiter(options = {}) {
  const windowMs = options.windowMs || 15 * 60 * 1000;
  const max = options.max || 100;
  const hits = new Map();

  return function (req, res, next) {
    const ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
    const now = Date.now();
    const timestamps = hits.get(ip) || [];

    const activeTimestamps = timestamps.filter(ts => now - ts < windowMs);
    if (activeTimestamps.length >= max) {
      return res.status(429).json({ error: 'Too many requests, please try again later.' });
    }

    activeTimestamps.push(now);
    hits.set(ip, activeTimestamps);
    next();
  };
}

export const authLimiter = rateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });
export const checkoutLimiter = rateLimiter({ windowMs: 15 * 60 * 1000, max: 50 });
export default rateLimiter;
