const Redis = require("ioredis-mock");

/* 

To run this file do

npm install --save-dev jest ioredis-mock
npx jest ./middleware/test/ratelimit.test.js

*/

// Mock the config first
jest.mock("../config/rateLimit.config", () => ({
  maxRequests: 5,
  windowInSeconds: 60,
  identifiers: {
    useIp: true,
    useUserId: true,
    useApiKey: true,
    useSessionId: true,
    useUserAgent: false, // Disabled for security
    useAcceptLanguage: false, // Disabled for security
  },
  useEntityId: true,
  failOpen: true,
  redis: {
    host: "localhost",
    port: 6379,
    keyPrefix: "ratelimit:",
  },
  advanced: {
    useForwardedFor: false,
    useLeftmostForwardedIp: true,
    trustedProxies: [],
  },
  includeRateLimitHeaders: true,
}));

// Mock the Redis client
jest.mock("ioredis", () => require("ioredis-mock"));

// Mock logger
jest.mock("../logger/logger", () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

const rateLimiter = require("../checks/ratelimit");

describe("Rate Limiter Tests", () => {
  let mockReq;
  let redisClient;

  beforeEach(async () => {
    // Get Redis instance and flush all data before each test
    const RedisMock = require("ioredis-mock");
    redisClient = new RedisMock();

    // Clear all Redis data
    await redisClient.flushall();

    // Create a fresh mock request for each test
    mockReq = {
      ip: "192.168.1.1",
      connection: { remoteAddress: "192.168.1.1" },
      headers: {
        "user-agent": "Mozilla/5.0",
        "accept-language": "en-US",
        "x-entity-id": "user123",
      },
      sessionID: "session-abc-123",
    };
  });

  afterEach(async () => {
    // Clean up after each test
    if (redisClient) {
      await redisClient.flushall();
    }
  });

  test("Should allow first 5 requests", async () => {
    for (let i = 1; i <= 5; i++) {
      const result = await rateLimiter(mockReq);

      expect(result.allowed).toBe(true);
      expect(result.current).toBe(i);
      expect(result.remaining).toBe(5 - i);
      expect(result.limit).toBe(5);

      console.log(`Request ${i}: ✅ Allowed (${result.remaining} remaining)`);
    }
  });

  test("Should block 6th request", async () => {
    // Make 5 allowed requests
    for (let i = 0; i < 5; i++) {
      await rateLimiter(mockReq);
    }

    // 6th request should be blocked
    const result = await rateLimiter(mockReq);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.current).toBe(6);

    console.log("Request 6: ❌ Rate Limited");
  });

  test("Should have separate limits for different entity IDs", async () => {
    // User 1 makes 5 requests
    const user1Req = {
      ...mockReq,
      headers: { ...mockReq.headers, "x-entity-id": "user1" },
    };

    for (let i = 0; i < 5; i++) {
      await rateLimiter(user1Req);
    }

    // User 1 should be blocked
    const user1Result = await rateLimiter(user1Req);
    expect(user1Result.allowed).toBe(false);

    // User 2 should still be allowed (different entity ID = different Redis key)
    const user2Req = {
      ...mockReq,
      headers: { ...mockReq.headers, "x-entity-id": "user2" },
    };
    const user2Result = await rateLimiter(user2Req);
    expect(user2Result.allowed).toBe(true);
    expect(user2Result.current).toBe(1); // First request for user2

    console.log("✅ Different users have independent limits");
  });

  test("Should create different buckets for different IPs (primary security)", async () => {
    // With default config: IP + SessionID are used
    // User-Agent and Accept-Language are IGNORED (disabled in config)

    const req1 = {
      ip: "192.168.1.1",
      connection: { remoteAddress: "192.168.1.1" },
      headers: {
        "x-entity-id": "user123",
      },
      sessionID: "session-abc-123",
    };

    // Different IP creates a different hash = different rate limit bucket
    const req2 = {
      ip: "10.0.0.1", // Different IP
      connection: { remoteAddress: "10.0.0.1" },
      headers: {
        "x-entity-id": "user123",
      },
      sessionID: "session-abc-123",
    };

    // Make 5 requests from IP 1 (max out this bucket)
    for (let i = 0; i < 5; i++) {
      await rateLimiter(req1);
    }

    // IP 1 is now rate limited
    const req1Result = await rateLimiter(req1);
    expect(req1Result.allowed).toBe(false);

    // IP 2 starts fresh (different hash = different bucket)
    const req2Result = await rateLimiter(req2);
    expect(req2Result.allowed).toBe(true);
    expect(req2Result.current).toBe(1); // Fresh counter

    console.log("✅ IP-based rate limiting: different IPs = different buckets");
  });

  test("Should ignore User-Agent changes (security feature)", async () => {
    // This is the fix for your DDoS concern!
    // Changing User-Agent should NOT bypass rate limits

    const req1 = {
      ...mockReq,
      headers: {
        ...mockReq.headers,
        "user-agent": "Mozilla/5.0 Firefox",
      },
    };

    const req2 = {
      ...mockReq,
      headers: {
        ...mockReq.headers,
        "user-agent": "Chrome/91.0", // Different user agent
      },
    };

    // Make 5 requests with first user agent
    for (let i = 0; i < 5; i++) {
      await rateLimiter(req1);
    }

    // Request with DIFFERENT user agent should STILL be rate limited
    // because User-Agent is not used in the hash (useUserAgent: false)
    const result = await rateLimiter(req2);
    expect(result.allowed).toBe(false); // Still blocked!
    expect(result.current).toBe(6); // Same counter

    console.log("✅ User-Agent rotation does NOT bypass rate limits");
    console.log("   This prevents DDoS attacks via user-agent spoofing");
  });

  test("Should track same user across requests with same fingerprint", async () => {
    // Same everything = same hash = same bucket
    const req1 = { ...mockReq };
    const req2 = { ...mockReq }; // Exact same

    // First request
    const result1 = await rateLimiter(req1);
    expect(result1.current).toBe(1);

    // Second request with exact same fingerprint
    const result2 = await rateLimiter(req2);
    expect(result2.current).toBe(2);

    console.log("✅ Same fingerprint = same rate limit bucket");
  });

  test("Should return proper reset time", async () => {
    const result = await rateLimiter(mockReq);

    expect(result.resetTime).toBeGreaterThan(Date.now());
    expect(result.resetTime).toBeLessThanOrEqual(Date.now() + 60000);

    console.log(`✅ Reset time: ${new Date(result.resetTime).toISOString()}`);
  });

  test("Should not crash on invalid request data", async () => {
    // Test with missing headers
    const invalidReq = {
      ip: "192.168.1.1",
      connection: { remoteAddress: "192.168.1.1" },
      headers: {},
      // No sessionID
    };

    try {
      const result = await rateLimiter(invalidReq);
      expect(result).toHaveProperty("allowed");
      expect(result).toHaveProperty("limit");
      console.log("✅ Handles invalid request data gracefully");
    } catch (error) {
      fail("Rate limiter should handle invalid data gracefully");
    }
  });

  test("Should decrement remaining counter correctly", async () => {
    const results = [];

    for (let i = 0; i < 5; i++) {
      const result = await rateLimiter(mockReq);
      results.push(result.remaining);
    }

    expect(results).toEqual([4, 3, 2, 1, 0]);
    console.log("✅ Remaining counter decrements correctly:", results);
  });

  test("Should set proper TTL on first request", async () => {
    const result = await rateLimiter(mockReq);

    expect(result.current).toBe(1);

    // Check that resetTime is approximately 60 seconds from now
    const expectedResetTime = Date.now() + 60000;
    const tolerance = 1000; // 1 second tolerance

    expect(result.resetTime).toBeGreaterThanOrEqual(
      expectedResetTime - tolerance
    );
    expect(result.resetTime).toBeLessThanOrEqual(expectedResetTime + tolerance);

    console.log("✅ TTL set correctly on first request");
  });

  test("Should use entity ID in Redis key for isolation", async () => {
    // This test verifies that entity ID is part of the rate limiting
    const entity1Req = {
      ...mockReq,
      headers: { ...mockReq.headers, "x-entity-id": "entity1" },
    };

    const entity2Req = {
      ...mockReq,
      headers: { ...mockReq.headers, "x-entity-id": "entity2" },
    };

    // Max out entity1
    for (let i = 0; i < 5; i++) {
      await rateLimiter(entity1Req);
    }

    const entity1Blocked = await rateLimiter(entity1Req);
    expect(entity1Blocked.allowed).toBe(false);

    // entity2 should be unaffected
    const entity2Allowed = await rateLimiter(entity2Req);
    expect(entity2Allowed.allowed).toBe(true);

    console.log("✅ Entity ID provides proper isolation between users");
  });

  test("Should track authenticated users separately", async () => {
    // Authenticated user
    const authReq = {
      ...mockReq,
      user: { id: "auth-user-123" },
    };

    // Anonymous user (same IP, different bucket due to user ID)
    const anonReq = {
      ...mockReq,
      // No user object
    };

    // Max out authenticated user
    for (let i = 0; i < 5; i++) {
      await rateLimiter(authReq);
    }

    const authResult = await rateLimiter(authReq);
    expect(authResult.allowed).toBe(false);

    // Anonymous user should have separate limit
    const anonResult = await rateLimiter(anonReq);
    expect(anonResult.allowed).toBe(true);
    expect(anonResult.current).toBe(1);

    console.log("✅ Authenticated users have separate rate limit buckets");
  });

  test("Should handle API key authentication", async () => {
    const apiKey1Req = {
      ...mockReq,
      headers: {
        ...mockReq.headers,
        "x-api-key": "key-123",
      },
    };

    const apiKey2Req = {
      ...mockReq,
      headers: {
        ...mockReq.headers,
        "x-api-key": "key-456",
      },
    };

    // Max out first API key
    for (let i = 0; i < 5; i++) {
      await rateLimiter(apiKey1Req);
    }

    const key1Result = await rateLimiter(apiKey1Req);
    expect(key1Result.allowed).toBe(false);

    // Second API key should have separate limit
    const key2Result = await rateLimiter(apiKey2Req);
    expect(key2Result.allowed).toBe(true);

    console.log("✅ Different API keys have separate rate limits");
  });
});
