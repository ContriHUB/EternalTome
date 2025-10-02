const logger = require("../logger/logger");
const Redis = require("ioredis");
const crypto = require("crypto");
const config = require("../config/rateLimit.config")

const redis = new Redis(config.redis);

/**
 * Extract the real client IP address
 * @param {Object} req - Express request object
 * @returns {string} - Client IP address
 */
function getClientIp(req) {
  if (config.advanced.useForwardedFor) {
    const forwardedFor = req.headers["x-forwarded-for"];
    if (forwardedFor) {
      const ips = forwardedFor.split(",").map((ip) => ip.trim());
      return config.advanced.useLeftmostForwardedIp
        ? ips[0]
        : ips[ips.length - 1];
    }
  }
  return req.ip || req.connection.remoteAddress;
}

/**
 * Generate a unique identifier for rate limiting based on configuration
 * @param {Object} req - Express request object
 * @returns {string} - Unique identifier hash
 */
function generateUserIdentifier(req) {
  const identifiers = [];

  // IP Address (primary identifier for DDoS protection)
  if (config.identifiers.useIp) {
    identifiers.push(getClientIp(req));
  }

  // User ID from authentication
  if (config.identifiers.useUserId && req.user && req.user.id) {
    identifiers.push(`user:${req.user.id}`);
  }

  // API Key authentication
  if (config.identifiers.useApiKey && req.headers["x-api-key"]) {
    identifiers.push(`apikey:${req.headers["x-api-key"]}`);
  }

  // Session ID
  if (config.identifiers.useSessionId && req.sessionID) {
    identifiers.push(`session:${req.sessionID}`);
  }

  // User-Agent (optional, easily spoofed - disabled by default)
  if (config.identifiers.useUserAgent) {
    identifiers.push(req.headers["user-agent"] || "unknown");
  }

  // Accept-Language (optional, easily spoofed - disabled by default)
  if (config.identifiers.useAcceptLanguage) {
    identifiers.push(req.headers["accept-language"] || "none");
  }

  // Ensure at least IP is included if no identifiers configured
  if (identifiers.length === 0) {
    identifiers.push(getClientIp(req));
  }

  // Create hash for consistent key generation
  const combined = identifiers.join("|");
  const hash = crypto
    .createHash("sha256")
    .update(combined)
    .digest("hex")
    .substring(0, 16);

  return hash;
}

/**
 * Rate limiter function with configurable identification
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} - { allowed: boolean, remaining: number, resetTime: number }
 */
async function rateLimiter(req) {
  try {
    const userHash = generateUserIdentifier(req);
    const ip = getClientIp(req);
    const entityId = config.useEntityId
      ? req.headers["x-entity-id"] || "anonymous"
      : "global";

    const redisKey = `${entityId}:${userHash}`;

    // Increment counter
    const current = await redis.incr(redisKey);

    // Set expiry on first request
    if (current === 1) {
      await redis.expire(redisKey, config.windowInSeconds);
      logger.info(
        `Rate limiting started for entity ${entityId}, hash ${userHash} (IP: ${ip}), expiry: ${config.windowInSeconds}s`
      );
    }

    // Get TTL for reset time
    const ttl = await redis.ttl(redisKey);
    const resetTime = Date.now() + ttl * 1000;
    const remaining = Math.max(0, config.maxRequests - current);

    // Block if limit exceeded
    if (current > config.maxRequests) {
      logger.warn(
        `Rate limit exceeded for entity ${entityId}, hash ${userHash} (IP: ${ip}). Count: ${current}/${config.maxRequests}`
      );
      return {
        allowed: false,
        remaining: 0,
        resetTime,
        current,
        limit: config.maxRequests,
      };
    }

    // Allow request
    logger.info(
      `Request allowed for entity ${entityId}, hash ${userHash} (IP: ${ip}). Count: ${current}/${config.maxRequests}`
    );
    return {
      allowed: true,
      remaining,
      resetTime,
      current,
      limit: config.maxRequests,
    };
  } catch (error) {
    logger.error(`Rate limiter error: ${error.message}`);
    // Fail open/closed based on configuration
    return {
      allowed: config.failOpen,
      remaining: config.failOpen ? config.maxRequests : 0,
      resetTime: Date.now() + config.windowInSeconds * 1000,
      current: 0,
      limit: config.maxRequests,
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
      // Add rate limit headers if configured
      if (config.includeRateLimitHeaders) {
        res.setHeader("X-RateLimit-Limit", result.limit);
        res.setHeader("X-RateLimit-Remaining", result.remaining);
        res.setHeader(
          "X-RateLimit-Reset",
          new Date(result.resetTime).toISOString()
        );
      }

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
      // Fail based on configuration
      if (config.failOpen) {
        next();
      } else {
        res.status(503).json({
          error: "Service Unavailable",
          message: "Rate limiting service is temporarily unavailable",
        });
      }
    });
}

module.exports = rateLimiter;
module.exports.middleware = rateLimiterMiddleware;
module.exports.generateUserIdentifier = generateUserIdentifier;
