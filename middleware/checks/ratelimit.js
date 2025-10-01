const logger = require("../logger/logger");
const Redis = require("ioredis");
const crypto = require("crypto");

const redis = new Redis();

const MAX_REQUESTS = 5;
const WINDOW_IN_SECONDS = 60;

/**
 * Generate a unique identifier for rate limiting based on multiple factors
 * @param {Object} req - Express request object
 * @returns {string} - Unique identifier hash
 */
function generateUserIdentifier(req) {
  const identifiers = [];

  // 1. IP Address (primary identifier)
  const ip = req.ip || req.connection.remoteAddress;
  identifiers.push(ip);

  // 2. User Agent (browser/client information)
  const userAgent = req.headers["user-agent"] || "unknown";
  identifiers.push(userAgent);

  // 3. User ID from authentication (if available)
  if (req.user && req.user.id) {
    identifiers.push(`user:${req.user.id}`);
  }

  // 4. API Key (if using API key authentication)
  if (req.headers["x-api-key"]) {
    identifiers.push(`apikey:${req.headers["x-api-key"]}`);
  }

  // 5. Session ID (if available)
  if (req.sessionID) {
    identifiers.push(`session:${req.sessionID}`);
  }

  // 6. Accept-Language (helps differentiate automated bots)
  const acceptLanguage = req.headers["accept-language"] || "none";
  identifiers.push(acceptLanguage);

  // Create a hash of combined identifiers for consistent key generation
  const combined = identifiers.join("|");
  const hash = crypto
    .createHash("sha256")
    .update(combined)
    .digest("hex")
    .substring(0, 16); // Use first 16 chars for readability

  return hash;
}

/**
 * Rate limiter function with enhanced user identification
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} - { allowed: boolean, remaining: number, resetTime: number }
 */
async function rateLimiter(req) {
  try {
    const userHash = generateUserIdentifier(req);
    const ip = req.ip || req.connection.remoteAddress;
    const entityId = req.headers["x-entity-id"] || "anonymous";

    // Combine hash with entity ID for even more precise tracking
    const redisKey = `ratelimit:${entityId}:${userHash}`;

    // Increment the counter
    const current = await redis.incr(redisKey);

    // If it's the first request, set expiry
    if (current === 1) {
      await redis.expire(redisKey, WINDOW_IN_SECONDS);
      logger.info(
        `Rate limiting started for entity ${entityId}, hash ${userHash} (IP: ${ip}), expiry: ${WINDOW_IN_SECONDS}s`
      );
    }

    // Get TTL for reset time information
    const ttl = await redis.ttl(redisKey);
    const resetTime = Date.now() + ttl * 1000;
    const remaining = Math.max(0, MAX_REQUESTS - current);

    // Block if limit exceeded
    if (current > MAX_REQUESTS) {
      logger.warn(
        `Rate limit exceeded for entity ${entityId}, hash ${userHash} (IP: ${ip}). Count: ${current}/${MAX_REQUESTS}`
      );
      return {
        allowed: false,
        remaining: 0,
        resetTime,
        current,
        limit: MAX_REQUESTS,
      };
    }

    // Allow request
    logger.info(
      `Request allowed for entity ${entityId}, hash ${userHash} (IP: ${ip}). Count: ${current}/${MAX_REQUESTS}`
    );
    return {
      allowed: true,
      remaining,
      resetTime,
      current,
      limit: MAX_REQUESTS,
    };
  } catch (error) {
    logger.error(`Rate limiter error: ${error.message}`);
    // Fail open - allow request if Redis is down
    return {
      allowed: true,
      remaining: MAX_REQUESTS,
      resetTime: Date.now() + WINDOW_IN_SECONDS * 1000,
      current: 0,
      limit: MAX_REQUESTS,
      error: true,
    };
  }
}

/**
 * Express middleware wrapper for rate limiter
 */
function rateLimiterMiddleware(req, res, next) {
  rateLimiter(req)
    .then((result) => {
      // Add rate limit headers
      res.setHeader("X-RateLimit-Limit", result.limit);
      res.setHeader("X-RateLimit-Remaining", result.remaining);
      res.setHeader(
        "X-RateLimit-Reset",
        new Date(result.resetTime).toISOString()
      );

      if (!result.allowed) {
        return res.status(429).json({
          error: "Too Many Requests",
          message: `Rate limit exceeded. Try again after ${new Date(
            result.resetTime
          ).toISOString()}`,
          retryAfter: Math.ceil((result.resetTime - Date.now()) / 1000),
        });
      }

      next();
    })
    .catch((error) => {
      logger.error(`Rate limiter middleware error: ${error.message}`);
      // Fail open
      next();
    });
}

module.exports = rateLimiter;
module.exports.middleware = rateLimiterMiddleware;
module.exports.generateUserIdentifier = generateUserIdentifier;
