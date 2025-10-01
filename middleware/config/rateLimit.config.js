/**
 * Rate Limiting Configuration
 * Configure which identifiers to use for rate limiting
 */

module.exports = {
  // Basic rate limiting settings
  maxRequests: 5,
  windowInSeconds: 60,

  // Identifier configuration - choose which factors to include
  identifiers: {
    // PRIMARY IDENTIFIERS (Recommended to keep enabled)
    // IP address - most important for DDoS protection
    useIp: true,

    // SECONDARY IDENTIFIERS (Optional, choose based on your use case)
    // Authenticated user ID - good for authenticated APIs
    useUserId: true,

    // API Key - useful for API key based authentication
    useApiKey: true,

    // Session ID - useful for session-based applications
    useSessionId: true,

    // WEAK IDENTIFIERS (Not recommended - easily spoofed/rotated)
    // User-Agent - CAN BE EASILY CHANGED, not recommended for DDoS protection
    // An attacker can rotate user agents to bypass rate limits
    useUserAgent: false,

    // Accept-Language - CAN BE EASILY CHANGED, not recommended
    useAcceptLanguage: false,
  },

  // Entity ID configuration
  // Entity ID can be used to separate rate limits by tenant/organization
  useEntityId: true,

  // Fail open or closed when Redis is unavailable
  // true = allow requests when Redis is down (fail open)
  // false = block requests when Redis is down (fail secure)
  failOpen: true,

  // Redis configuration
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || undefined,
    db: process.env.REDIS_DB || 0,
    keyPrefix: "ratelimit:",
  },

  // Advanced options
  advanced: {
    // Include forwarded IPs (X-Forwarded-For) - use with caution
    // Only enable if behind a trusted proxy
    useForwardedFor: false,

    // Use the leftmost IP in X-Forwarded-For (original client IP)
    // Only relevant if useForwardedFor is true
    useLeftmostForwardedIp: true,

    // Trusted proxy IPs - only use forwarded headers from these IPs
    trustedProxies: [],
  },

  // Response headers configuration
  includeRateLimitHeaders: true,
};
