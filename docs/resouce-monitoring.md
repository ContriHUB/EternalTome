# Enhanced Resource Monitoring Configuration Guide

## Overview

This system provides flexible, configurable resource monitoring with three execution modes that balance security, isolation, and performance.

## Execution Modes

### 1. **Thread Mode** (Fastest, Lower Isolation)
- Uses worker threads for execution
- **Latency**: ~1-5ms overhead
- **Isolation**: Process-level only
- **Best for**: Trusted requests, low-risk operations

### 2. **Docker Mode** (Slowest, Highest Isolation)
- Spins up Docker containers for each request
- **Latency**: ~50-200ms overhead (cold start), ~20-50ms (warm containers)
- **Isolation**: Complete OS-level isolation
- **Best for**: Untrusted code, high-risk operations

### 3. **Hybrid Mode** (Recommended)
- Dynamically switches between Thread and Docker based on risk assessment
- **Latency**: Variable (1-200ms depending on risk)
- **Isolation**: Adaptive
- **Best for**: Production environments with mixed trust levels

## Configuration

### Environment Variables

```bash
# Execution mode: 'thread', 'docker', or 'hybrid'
EXECUTION_MODE=hybrid

# Docker configuration
DOCKER_ENABLED=true
DOCKER_IMAGE=node:18-alpine
DOCKER_MEMORY_LIMIT=256m
DOCKER_CPU_LIMIT=0.5
DOCKER_TIMEOUT=30000
DOCKER_REUSE=true
DOCKER_WARM_POOL=3

# Resource limits
MEMORY_LIMIT_MB=120
MEMORY_CHECK_INTERVAL=5000
MAX_EXECUTION_TIME=4000

# Hybrid mode triggers (when to use Docker)
DOCKER_FOR_UNTRUSTED=true
DOCKER_FOR_HIGH_RESOURCE=true
DOCKER_FOR_SUSPICIOUS=true
DOCKER_FOR_NEW=true

# JWT Secret
SECRET_KEY=your-secret-key-here
```

### Programmatic Configuration

```javascript
const { createConfig } = require('./config/resource-monitoring');

const config = createConfig({
  executionMode: 'hybrid',
  
  docker: {
    enabled: true,
    memoryLimit: '512m',  // Increase for heavy workloads
    cpuLimit: '1.0',
    warmPoolSize: 5       // More warm containers = lower latency
  },
  
  limits: {
    execution: {
      maxTimeMS: 10000    // 10 second timeout
    }
  },
  
  hybrid: {
    riskThresholds: {
      low: 30,
      medium: 60,
      high: 80
    }
  }
});
```

## Performance Comparison

| Mode | Cold Start | Warm Start | Memory Isolation | CPU Isolation | Network Isolation |
|------|-----------|------------|------------------|---------------|-------------------|
| Thread | 1-5ms | 1-5ms | ❌ Shared | ❌ Shared | ❌ Shared |
| Docker | 100-200ms | 20-50ms | ✅ Isolated | ✅ Isolated | ✅ Isolated |
| Hybrid | 1-200ms | 1-50ms | ⚡ Adaptive | ⚡ Adaptive | ⚡ Adaptive |

## Risk-Based Execution (Hybrid Mode)

The hybrid mode calculates a risk score (0-100) for each request based on:

1. **Entity Trust Level** (+30 points for new entities)
2. **Historical Behavior** (+20 points for high failure rate)
3. **Resource Consumption** (+15 points for large payloads)
4. **Suspicious Patterns** (+20 points for dangerous keywords)
5. **IP Reputation** (+25 points for flagged IPs)

### Risk Thresholds

- **0-30 (Low)**: Execute in threads (fast)
- **30-60 (Medium)**: Check specific criteria, may use Docker
- **60-80 (High)**: Use Docker for isolation
- **80+ (Critical)**: Always use Docker

## Usage Examples

### Example 1: Trusted API (Thread Mode)

```javascript
// .env
EXECUTION_MODE=thread
DOCKER_ENABLED=false
```

**Use case**: Internal microservices, known clients
**Latency**: ~1-5ms overhead
**Security**: Basic process isolation

### Example 2: Public API (Hybrid Mode)

```javascript
// .env
EXECUTION_MODE=hybrid
DOCKER_ENABLED=true
DOCKER_WARM_POOL=5
DOCKER_FOR_NEW=true
```

**Use case**: Public APIs with mixed trust levels
**Latency**: 1-50ms for trusted, 20-100ms for untrusted
**Security**: Adaptive isolation

### Example 3: Code Execution Platform (Docker Mode)

```javascript
// .env
EXECUTION_MODE=docker
DOCKER_ENABLED=true
DOCKER_MEMORY_LIMIT=512m
DOCKER_CPU_LIMIT=1.0
DOCKER_REUSE=false  // Fresh container for each request
```

**Use case**: Serverless functions, user-submitted code
**Latency**: ~100-200ms per request
**Security**: Complete isolation

## Installation

### Prerequisites

```bash
# For Docker mode
docker --version  # Docker must be installed

# Node dependencies
npm install dockerode workerpool
```

### Setup

```bash
# 1. Install dependencies
npm install

# 2. Build Docker image (if using Docker mode)
docker pull node:18-alpine

# 3. Configure environment
cp .env.example .env
nano .env

# 4. Start application
npm start
```

## Monitoring & Statistics

### Get Execution Stats

```javascript
// GET /api/stats
// Headers: Authorization: Bearer <token>

{
  "entityId": "user-123",
  "stats": {
    "totalRequests": 150,
    "successfulRequests": 145,
    "failedRequests": 5,
    "avgExecutionTime": 45.2,
    "failureRate": 0.033,
    "resourceViolations": 1
  },
  "currentMode": "hybrid"
}
```

### Logging

```javascript
const logger = require('./logger/logger');

// View execution mode decisions
logger.info('Executing request in docker mode (risk score: 75)');

// View resource warnings
logger.warn('Memory limit exceeded: 125MB / 120MB');
```

## Performance Optimization Tips

### For Low Latency (Thread Mode)

```javascript
{
  executionMode: 'thread',
  threadPool: {
    minWorkers: 8,    // Keep workers ready
    maxWorkers: 16
  }
}
```

### For High Security (Docker Mode)

```javascript
{
  executionMode: 'docker',
  docker: {
    reuseContainers: false,  // Fresh container each time
    networkMode: 'none',      // No network access
    memoryLimit: '256m'
  }
}
```

### For Balanced (Hybrid Mode)

```javascript
{
  executionMode: 'hybrid',
  docker: {
    reuseContainers: true,   // Reuse for speed
    warmPoolSize: 5,         // Keep 5 containers warm
    timeout: 30000
  },
  hybrid: {
    riskThresholds: {
      low: 20,      // More aggressive Docker usage
      medium: 50,
      high: 70
    }
  }
}
```

## Docker Container Pool Management

The warm pool keeps containers ready to reduce cold start latency:

- **Without warm pool**: 100-200ms cold start
- **With warm pool**: 20-50ms warm start

```javascript
// Optimal warm pool size calculation
warmPoolSize = Math.ceil(avgRequestsPerSecond * avgExecutionTimeSeconds)

// Example: 10 req/s * 0.5s execution = 5 warm containers
```

## Security Considerations

### Thread Mode
- ⚠️ Shared memory space
- ⚠️ Shared file system
- ⚠️ Can access Node.js APIs
- ✅ Fast execution

### Docker Mode
- ✅ Isolated memory
- ✅ Isolated file system (read-only)
- ✅ Network isolation
- ✅ Resource limits enforced at OS level
- ⚠️ Higher latency

### Hybrid Mode
- ✅ Best of both worlds
- ✅ Risk-based adaptation
- ✅ Performance when safe
- ✅ Security when needed

## Troubleshooting

### High Latency in Docker Mode

```bash
# Increase warm pool
DOCKER_WARM_POOL=10

# Enable container reuse
DOCKER_REUSE=true
```

### Memory Leaks

```bash
# Lower memory limit
MEMORY_LIMIT_MB=80

# Shorter check interval
MEMORY_CHECK_INTERVAL=3000
```

### Docker Daemon Issues

```bash
# Check Docker is running
docker ps

# Check image exists
docker images | grep node

# Test container creation
docker run --rm node:18-alpine node --version
```

## Migration Guide

### From Pure Thread Pool

```javascript
// Before
const pool = require('./worker/worker-pool');

// After
const { executor } = require('./middleware');
// Executor handles thread/docker selection automatically
```

### Configuration Changes

```javascript
// Old (thread-only)
const pool = workerpool.pool('./worker.js', {
  minWorkers: 4,
  maxWorkers: 6
});

// New (hybrid with backward compatibility)
const executor = new HybridExecutor({
  executionMode: 'thread',  // Same as before
  threadPool: {
    minWorkers: 4,
    maxWorkers: 6
  }
});
```

## Benchmarks

Tested on: Intel i7, 16GB RAM, Docker 24.0

| Scenario | Thread | Docker (cold) | Docker (warm) | Hybrid |
|----------|--------|---------------|---------------|---------|
| Simple GET | 2ms | 150ms | 25ms | 2-25ms |
| JSON Processing | 5ms | 180ms | 35ms | 5-35ms |
| Heavy Computation | 850ms | 920ms | 870ms | 850-920ms |
| Malicious Request | N/A | 160ms | 30ms | 30-160ms |

## Contributing

When adding new security checks, update the risk scoring:

```javascript
// In hybrid-executor.js
calculateRiskScore(req) {
  let score = 0;
  
  // Add your custom risk factors
  if (req.headers['x-custom-risk']) {
    score += 15;
  }
  
  return Math.min(score, 100);
}
```

## License

MIT