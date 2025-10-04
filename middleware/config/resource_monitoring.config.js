// config/resource-monitoring.js
const os = require("os");

/**
 * Resource monitoring configuration with flexible execution modes
 *
 * Execution Modes:
 * - 'thread': Uses worker threads (fast, lower isolation)
 * - 'process': Uses child processes (moderate isolation)
 * - 'docker': Uses Docker containers (high isolation, slower)
 * - 'hybrid': Dynamic switching based on request risk profile
 */

const EXECUTION_MODES = {
  THREAD: "thread",
  PROCESS: "process",
  DOCKER: "docker",
  HYBRID: "hybrid",
};

const defaultConfig = {
  // Primary execution mode
  executionMode: EXECUTION_MODES.THREAD,

  // Thread pool configuration (for thread/process modes)
  threadPool: {
    minWorkers: 4,
    maxWorkers: 6,
    maxQueueSize: 100,
    workerTerminationTimeout: 5000,
  },

  // Docker configuration (for docker/hybrid modes)
  docker: {
    enabled: false,
    image: "node:18-alpine",
    memoryLimit: "256m",
    cpuLimit: "0.5",
    timeout: 30000,
    networkMode: "none", // Isolate network access
    removeOnExit: true,
    maxContainers: 10,
    reuseContainers: true, // Keep warm containers
    warmPoolSize: 3, // Number of pre-warmed containers
  },

  // Resource limits (applied to all modes)
  limits: {
    memory: {
      maxMB: 120,
      warningThresholdMB: 100,
      checkIntervalMS: 5000,
    },
    cpu: {
      maxPercent: 90,
      warningThresholdPercent: 75,
    },
    execution: {
      maxTimeMS: 4000,
      warningTimeMS: 3000,
    },
  },

  // Hybrid mode configuration
  hybrid: {
    // Criteria for switching to Docker
    useDockerWhen: {
      untrustedSource: true,
      highResourceRequest: true,
      suspiciousPatterns: true,
      newEntity: true, // First-time users
    },
    // Risk scoring thresholds
    riskThresholds: {
      low: 30,
      medium: 60,
      high: 80,
    },
  },

  // Monitoring configuration
  monitoring: {
    enabled: true,
    detailedMetrics: false,
    logLevel: "info", // 'debug', 'info', 'warn', 'error'
    alertOnThreshold: true,
  },
};

module.exports = {
  EXECUTION_MODES,
  defaultConfig,

  // Validate and merge user configuration
  createConfig: (userConfig = {}) => {
    return {
      ...defaultConfig,
      ...userConfig,
      threadPool: {
        ...defaultConfig.threadPool,
        ...userConfig.threadPool,
      },
      docker: {
        ...defaultConfig.docker,
        ...userConfig.docker,
      },
      limits: {
        memory: {
          ...defaultConfig.limits.memory,
          ...userConfig.limits?.memory,
        },
        cpu: {
          ...defaultConfig.limits.cpu,
          ...userConfig.limits?.cpu,
        },
        execution: {
          ...defaultConfig.limits.execution,
          ...userConfig.limits?.execution,
        },
      },
      hybrid: {
        ...defaultConfig.hybrid,
        ...userConfig.hybrid,
      },
      monitoring: {
        ...defaultConfig.monitoring,
        ...userConfig.monitoring,
      },
    };
  },
};
