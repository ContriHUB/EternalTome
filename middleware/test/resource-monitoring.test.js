const HybridExecutor = require("../executor/hybrid-executor");
const DockerExecutor = require("../executor/docker-executor");
const {
  createConfig,
  EXECUTION_MODES,
} = require("../config/resource_monitoring.config");

// Helper to quickly create a req object
function mkReq({
  entityId = "user",
  path = "/",
  body = {},
  query = {},
  headers = {},
  cookies = {},
} = {}) {
  return {
    path,
    body,
    query,
    cookies,
    headers: { "x-entity-id": entityId, ...headers },
  };
}

describe("HybridExecutor - Extensive Tests", () => {
  let executor;

  describe("Execution Modes", () => {
    test("always returns thread mode if config set", () => {
      executor = new HybridExecutor(createConfig({ executionMode: "thread" }));
      expect(executor.determineExecutionMode(mkReq())).toBe("thread");
    });

    test("always returns docker mode if config set", () => {
      executor = new HybridExecutor(
        createConfig({ executionMode: "docker", docker: { enabled: true } })
      );
      expect(executor.determineExecutionMode(mkReq())).toBe("docker");
    });

    test("hybrid: new entity triggers docker when newEntity=true", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 60, medium: 10 },
            useDockerWhen: { newEntity: true, suspiciousPatterns: false },
          },
        })
      );
      expect(
        executor.determineExecutionMode(mkReq({ entityId: "brand-new" }))
      ).toBe("docker");
    });

    test("hybrid: new entity, newEntity=false falls back to thread", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 60, medium: 10 },
            useDockerWhen: { newEntity: false, suspiciousPatterns: false },
          },
        })
      );
      expect(
        executor.determineExecutionMode(mkReq({ entityId: "brand-new" }))
      ).toBe("thread");
    });

    test("hybrid: high resource triggers docker", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 100, medium: 10 },
            useDockerWhen: { highResourceRequest: true },
          },
        })
      );
      expect(
        executor.determineExecutionMode(
          mkReq({ path: "/compute/process", body: { data: "x".repeat(60001) } })
        )
      ).toBe("docker");
    });

    test("hybrid: path alone doesn't trigger docker if not high resource", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 100, medium: 10 },
            useDockerWhen: { highResourceRequest: true },
          },
        })
      );
      expect(
        executor.determineExecutionMode(
          mkReq({ path: "/compute/process", body: { data: "x" } })
        )
      ).toBe("thread");
    });

    test("hybrid: suspiciousPatterns triggers docker", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 100, medium: 10 },
            useDockerWhen: { suspiciousPatterns: true },
          },
        })
      );
      expect(
        executor.determineExecutionMode(mkReq({ query: { exec: "system" } }))
      ).toBe("docker");
    });

    test("hybrid: suspiciousPatterns ignored if false", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 100, medium: 10 },
            useDockerWhen: { suspiciousPatterns: false },
          },
        })
      );
      expect(
        executor.determineExecutionMode(mkReq({ query: { exec: "system" } }))
      ).toBe("thread");
    });

    test("hybrid: high risk triggers docker (failureRate, avgExecutionTime, resourceViolations)", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 20, medium: 10 },
            useDockerWhen: {},
          },
        })
      );
      executor.requestStats.set("bad-user", {
        totalRequests: 10,
        successfulRequests: 2,
        failedRequests: 8,
        failureRate: 0.8,
        avgExecutionTime: 5000,
        resourceViolations: 5,
        lastRequestTime: Date.now(),
      });
      expect(
        executor.determineExecutionMode(mkReq({ entityId: "bad-user" }))
      ).toBe("docker");
    });

    test("hybrid: medium risk returns thread if useDockerWhen doesn't match", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 100, medium: 1 },
            useDockerWhen: { suspiciousPatterns: false },
          },
        })
      );
      executor.requestStats.set("med-user", {
        totalRequests: 100,
        successfulRequests: 90,
        failedRequests: 10,
        failureRate: 0.1,
        avgExecutionTime: 1000,
        resourceViolations: 0,
        lastRequestTime: Date.now(),
      });
      expect(
        executor.determineExecutionMode(mkReq({ entityId: "med-user" }))
      ).toBe("thread");
    });

    test("hybrid: disables docker if config.docker.enabled is false", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: false },
        })
      );
      expect(executor.determineExecutionMode(mkReq())).toBe("thread");
    });

    test("hybrid: risk below medium returns thread", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
          hybrid: {
            riskThresholds: { high: 50, medium: 20 },
            useDockerWhen: { suspiciousPatterns: false },
          },
        })
      );
      executor.requestStats.set("low-user", {
        totalRequests: 100,
        successfulRequests: 99,
        failedRequests: 1,
        failureRate: 0.01,
        avgExecutionTime: 10,
        resourceViolations: 0,
        lastRequestTime: Date.now(),
      });
      expect(
        executor.determineExecutionMode(mkReq({ entityId: "low-user" }))
      ).toBe("thread");
    });

    // Add more edge cases for execution mode selection
    test("hybrid: suspicious IP triggers higher risk", () => {
      executor = new HybridExecutor(
        createConfig({
          executionMode: "hybrid",
          docker: { enabled: true },
        })
      );
      const req = mkReq({
        entityId: "ip-risk",
        headers: { "x-suspicious-ip": "true" },
      });
      expect(executor.calculateRiskScore(req)).toBeGreaterThanOrEqual(25 + 30);
    });

    test("hybrid: path with both compute and body triggers high resource", () => {
      executor = new HybridExecutor(
        createConfig({ executionMode: "hybrid", docker: { enabled: true } })
      );
      const req = mkReq({
        path: "/compute/process",
        body: { data: "x".repeat(60000) },
      });
      expect(executor.isHighResourceRequest(req)).toBe(true);
    });

    test("hybrid: path with neither compute nor large body is not high resource", () => {
      executor = new HybridExecutor(
        createConfig({ executionMode: "hybrid", docker: { enabled: true } })
      );
      const req = mkReq({
        path: "/simple/process",
        body: { data: "x" },
      });
      expect(executor.isHighResourceRequest(req)).toBe(false);
    });

    // Test edge: very large payload
    test("hybrid: very large payload triggers risk cap", () => {
      executor = new HybridExecutor(
        createConfig({ executionMode: "hybrid", docker: { enabled: true } })
      );
      const req = mkReq({
        entityId: "large",
        body: { data: "x".repeat(999999) },
        headers: { "x-suspicious-ip": "true" },
        query: { exec: "eval" },
      });
      expect(executor.calculateRiskScore(req)).toBeLessThanOrEqual(100);
    });
  });

  describe("Risk Score Calculation", () => {
    beforeEach(() => {
      executor = new HybridExecutor(
        createConfig({ executionMode: "hybrid", docker: { enabled: true } })
      );
    });

    test("all risk factors applied", () => {
      executor.requestStats.set("risky", {
        totalRequests: 80,
        successfulRequests: 10,
        failedRequests: 70,
        failureRate: 0.875,
        avgExecutionTime: 4000,
        resourceViolations: 5,
        lastRequestTime: Date.now(),
      });
      const req = mkReq({
        entityId: "risky",
        body: { data: "x".repeat(12000) },
        query: { exec: "eval system" },
        headers: { "x-suspicious-ip": "true" },
      });
      expect(executor.calculateRiskScore(req)).toBe(100); // capped
    });

    test("suspiciousPatterns: single triggers +20", () => {
      const score = executor.calculateRiskScore(
        mkReq({ query: { exec: "eval" } })
      );
      expect(score).toBeGreaterThanOrEqual(20 + 30);
    });

    test("large body size: >10000 triggers +15", () => {
      const score = executor.calculateRiskScore(
        mkReq({ body: { data: "a".repeat(10001) } })
      );
      expect(score).toBeGreaterThanOrEqual(15 + 30);
    });

    test("resourceViolations > 3 triggers +25", () => {
      executor.requestStats.set("vuser", {
        totalRequests: 10,
        successfulRequests: 3,
        failedRequests: 7,
        resourceViolations: 4,
        failureRate: 0.7,
        avgExecutionTime: 100,
        lastRequestTime: Date.now(),
      });
      const score = executor.calculateRiskScore(mkReq({ entityId: "vuser" }));
      expect(score).toBeGreaterThanOrEqual(25 + 20 + 30);
    });

    test("avgExecutionTime > 3000 triggers +15", () => {
      executor.requestStats.set("slow", {
        totalRequests: 10,
        successfulRequests: 7,
        failedRequests: 3,
        resourceViolations: 0,
        failureRate: 0.3,
        avgExecutionTime: 3001,
        lastRequestTime: Date.now(),
      });
      const score = executor.calculateRiskScore(mkReq({ entityId: "slow" }));
      expect(score).toBeGreaterThanOrEqual(15 + 30);
    });

    test("failureRate > 0.5 triggers +20", () => {
      executor.requestStats.set("fail", {
        totalRequests: 10,
        successfulRequests: 3,
        failedRequests: 7,
        resourceViolations: 0,
        failureRate: 0.7,
        avgExecutionTime: 10,
        lastRequestTime: Date.now(),
      });
      const score = executor.calculateRiskScore(mkReq({ entityId: "fail" }));
      expect(score).toBeGreaterThanOrEqual(20 + 30);
    });

    test("suspiciousPatterns with suspiciousIp triggers +45", () => {
      const score = executor.calculateRiskScore(
        mkReq({
          query: { exec: "eval" },
          headers: { "x-suspicious-ip": "true" },
        })
      );
      expect(score).toBeGreaterThanOrEqual(20 + 25 + 30);
    });

    test("multiple risk factors sum up to cap", () => {
      executor.requestStats.set("max", {
        totalRequests: 100,
        successfulRequests: 1,
        failedRequests: 99,
        resourceViolations: 999,
        failureRate: 0.99,
        avgExecutionTime: 10000,
        lastRequestTime: Date.now(),
      });
      const score = executor.calculateRiskScore(
        mkReq({
          entityId: "max",
          body: { data: "x".repeat(1000000) },
          query: { exec: "eval system" },
          headers: { "x-suspicious-ip": "true" },
        })
      );
      expect(score).toBe(100);
    });
  });

  describe("Statistics Tracking", () => {
    beforeEach(() => {
      executor = new HybridExecutor(
        createConfig({ executionMode: "hybrid", docker: { enabled: true } })
      );
    });

    test("updateStats: increments totalRequests, successfulRequests", () => {
      executor.updateStats("entity", { success: true, executionTime: 10 });
      let stats = executor.getStats("entity");
      expect(stats.totalRequests).toBe(1);
      expect(stats.successfulRequests).toBe(1);
      expect(stats.failedRequests).toBe(0);
    });

    test("updateStats: increments failedRequests", () => {
      executor.updateStats("entity", { success: false, executionTime: 6 });
      let stats = executor.getStats("entity");
      expect(stats.failedRequests).toBe(1);
      expect(stats.successfulRequests).toBe(0);
    });

    test("updateStats: increments resourceViolations on error", () => {
      executor.updateStats("entity", {
        success: false,
        executionTime: 10,
        error: "resource exceeded",
      });
      let stats = executor.getStats("entity");
      expect(stats.resourceViolations).toBe(1);
    });

    test("updateStats: calculates failureRate", () => {
      executor.updateStats("f", { success: false, executionTime: 1 });
      executor.updateStats("f", { success: true, executionTime: 2 });
      let stats = executor.getStats("f");
      expect(stats.failureRate).toBeCloseTo(0.5);
    });

    test("updateStats: calculates avgExecutionTime", () => {
      executor.updateStats("e", { success: true, executionTime: 10 });
      executor.updateStats("e", { success: true, executionTime: 30 });
      let stats = executor.getStats("e");
      expect(stats.avgExecutionTime).toBe(20);
    });

    test("getStats: returns null for unknown user", () => {
      expect(executor.getStats("ghost-user")).toBeNull();
    });

    test("updateStats: removes old stats after an hour", () => {
      executor.requestStats.set("old", {
        totalRequests: 1,
        successfulRequests: 1,
        failedRequests: 0,
        totalExecutionTime: 1,
        resourceViolations: 0,
        lastRequestTime: Date.now() - 2 * 3600000,
      });
      executor.updateStats("old", { success: true, executionTime: 1 });
      expect(executor.requestStats.has("old")).toBe(false);
    });
  });

  describe("Config", () => {
    test("config: merges custom threadPool", () => {
      const config = createConfig({
        threadPool: { minWorkers: 3, maxWorkers: 9 },
      });
      expect(config.threadPool.minWorkers).toBe(3);
      expect(config.threadPool.maxWorkers).toBe(9);
    });

    test("config: merges custom hybrid riskThresholds", () => {
      const config = createConfig({
        hybrid: { riskThresholds: { high: 90, medium: 50 } },
      });
      expect(config.hybrid.riskThresholds.high).toBe(90);
      expect(config.hybrid.riskThresholds.medium).toBe(50);
    });

    test("config: merges custom docker", () => {
      const config = createConfig({
        docker: { enabled: true, memoryLimit: "1g", cpuLimit: "2" },
      });
      expect(config.docker.enabled).toBe(true);
      expect(config.docker.memoryLimit).toBe("1g");
      expect(config.docker.cpuLimit).toBe("2");
    });

    test("config: default values", () => {
      const config = createConfig();
      expect(config.executionMode).toBeDefined();
      expect(config.threadPool).toBeDefined();
      expect(config.docker).toBeDefined();
      expect(config.limits).toBeDefined();
      expect(config.hybrid).toBeDefined();
    });
  });
});

describe("DockerExecutor - Extensive", () => {
  test("parseMemoryLimit: handles m, g, bad", () => {
    const config = {
      docker: { image: "node", memoryLimit: "512m", cpuLimit: "1.0" },
    };
    const exec = new DockerExecutor(config);
    expect(exec.parseMemoryLimit("512m")).toBe(512 * 1024 * 1024);
    expect(exec.parseMemoryLimit("1g")).toBe(1024 * 1024 * 1024);
    expect(exec.parseMemoryLimit("2g")).toBe(2 * 1024 * 1024 * 1024);
    expect(exec.parseMemoryLimit("bad")).toBe(256 * 1024 * 1024);
    expect(exec.parseMemoryLimit("999m")).toBe(999 * 1024 * 1024);
  });

  test("parseCpuLimit: handles various values", () => {
    const config = {
      docker: { image: "node", memoryLimit: "512m", cpuLimit: "1.0" },
    };
    const exec = new DockerExecutor(config);
    expect(exec.parseCpuLimit("1")).toBe(1e9);
    expect(exec.parseCpuLimit("0.5")).toBe(0.5e9);
    expect(exec.parseCpuLimit("2")).toBe(2e9);
    expect(exec.parseCpuLimit("0")).toBe(0);
    expect(exec.parseCpuLimit("4.5")).toBe(4.5e9);
  });

  test("createContainer: returns a container instance", async () => {
    const config = {
      docker: {
        image: "node:18-alpine",
        memoryLimit: "256m",
        cpuLimit: "1.0",
        enabled: true,
        reuseContainers: false,
      },
    };
    const exec = new DockerExecutor(config);
    if (typeof exec.docker.createContainer === "function") {
      // This test only works if Docker is running and accessible
      try {
        const container = await exec.createContainer();
        expect(container).toBeDefined();
        await exec.cleanup(container);
      } catch (err) {
        // If docker is not available, skip
        expect(err.message).toMatch(
          /connect|ENOENT|Cannot connect to the Docker daemon/i
        );
      }
    }
  });

  test("returnToPool: stops/reuses/cleans up as needed", async () => {
    const config = {
      docker: {
        image: "node:18-alpine",
        memoryLimit: "256m",
        cpuLimit: "1.0",
        enabled: true,
        reuseContainers: true,
        warmPoolSize: 1,
      },
    };
    const exec = new DockerExecutor(config);
    if (typeof exec.docker.createContainer === "function") {
      try {
        const container = await exec.createContainer();
        await exec.returnToPool(container);
        expect(exec.warmPool.length).toBeLessThanOrEqual(
          config.docker.warmPoolSize
        );
      } catch (err) {
        expect(err.message).toMatch(
          /connect|ENOENT|Cannot connect to the Docker daemon/i
        );
      }
    }
  });

  test("cleanup: handles no container gracefully", async () => {
    const config = {
      docker: { image: "node", memoryLimit: "512m", cpuLimit: "1.0" },
    };
    const exec = new DockerExecutor(config);
    await expect(exec.cleanup(null)).resolves.toBeUndefined();
  });

  test("initWarmPool: creates up to warmPoolSize", async () => {
    const config = {
      docker: {
        image: "node:18-alpine",
        memoryLimit: "256m",
        cpuLimit: "1.0",
        enabled: true,
        reuseContainers: true,
        warmPoolSize: 2,
      },
    };
    const exec = new DockerExecutor(config);
    if (typeof exec.docker.createContainer === "function") {
      try {
        await exec.initWarmPool();
        expect(exec.warmPool.length).toBeLessThanOrEqual(
          config.docker.warmPoolSize
        );
        // Cleanup
        await exec.shutdown();
      } catch (err) {
        expect(err.message).toMatch(
          /connect|ENOENT|Cannot connect to the Docker daemon/i
        );
      }
    }
  });

  test("shutdown: cleans up warm pool", async () => {
    const config = {
      docker: {
        image: "node:18-alpine",
        memoryLimit: "256m",
        cpuLimit: "1.0",
        enabled: true,
        reuseContainers: true,
        warmPoolSize: 1,
      },
    };
    const exec = new DockerExecutor(config);
    exec.warmPool = [];
    await expect(exec.shutdown()).resolves.toBeUndefined();
  });

  test("generateExecutionScript: produces valid JS string", () => {
    const config = {
      docker: { image: "node", memoryLimit: "512m", cpuLimit: "1.0" },
    };
    const exec = new DockerExecutor(config);
    const script = exec.generateExecutionScript(
      JSON.stringify({ request: {}, handler: "handler.js" })
    );
    expect(typeof script).toBe("string");
    expect(script).toMatch(/const payload/);
    expect(script).toMatch(/require\(payload\.handler\)/);
  });

  // Add more edge and error cases if needed
});

// If you want even more, you can further test error handling, shutdown logic, pool limits, etc.
