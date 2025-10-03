# SQL Injection Detector

A high-performance, configurable SQL injection detection system for Node.js applications with multiple detection pipelines.

## Table of Contents

- [Overview](#overview)
- [Architecture & Design Philosophy](#architecture--design-philosophy)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detection Pipelines](#detection-pipelines)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Performance](#performance)
- [Testing](#testing)

---

## Overview

This SQL injection detector provides three progressive detection pipelines:

1. **Bloom Filter Only** - Ultra-fast preliminary filtering
2. **Bloom Filter + Heuristic Matching** - Balanced performance and accuracy (default)
3. **Bloom Filter + Heuristic + AST Parser** - Maximum security for critical endpoints

### Why This Approach?

**Bloom Filters** are probabilistic data structures that can guarantee "definitely not malicious" but may occasionally flag safe inputs as suspicious (false positives). This is acceptable because:
- False positives are rare with proper configuration
- They provide O(1) lookup time for instant filtering
- 100% of truly malicious patterns will be caught (no false negatives)
- Safe inputs that pass bloom filter skip expensive heuristic checks

The multi-stage pipeline maximizes both security and performance.

---

## Architecture & Design Philosophy

### 1. Bloom Filter Stage

**Purpose**: Fast initial filtering to catch obviously safe inputs

**How it works**:
- Whitelist of common safe SQL keywords (select, from, where, etc.)
- Input is tokenized and each token is hashed using multiple hash functions
- If suspicious token ratio exceeds 30%, proceed to next stage
- Otherwise, input is approved immediately

**Why Bloom Filters?**
- **Speed**: O(k) where k = number of hash functions (typically 3)
- **Memory efficient**: Fixed-size bit array regardless of whitelist size
- **No false negatives**: Will always detect potential threats
- **Acceptable false positives**: ~3% with proper configuration

```
Input: "select * from users"
Tokens: ["select", "from", "users"]
Bloom check: All tokens in whitelist → PASS (skip heuristic)

Input: "admin'-- malicious"
Tokens: ["admin'--", "malicious"]
Bloom check: Suspicious tokens detected → PROCEED to heuristic
```

### 2. Heuristic Matching Stage

**Purpose**: Weighted scoring of injection patterns

**How it works**:
- Multiple regex patterns detect known attack vectors
- Each detection adds weighted points to a score
- Score exceeds threshold → block request
- Score below threshold → pass (or proceed to AST if enabled)

**Detection Categories**:
1. SQL Keywords (weight: 4)
2. Comment Patterns (weight: 3)
3. Quote Anomalies (weight: 3)
4. Classic Injection Patterns (weight: 6)
5. UNION Attacks (weight: 6)
6. Stacked Queries (weight: 5)
7. Encoded Characters (weight: 3)
8. Hex Patterns (weight: 4)
9. Time-based attacks (weight: 8)
10. Boolean blind injection (weight: 4)

**Default Threshold**: 5 (aggressive security posture)

### 3. AST Parser Stage (Optional)

**Purpose**: Deep structural analysis for critical endpoints

**How it works**:
- Parses input as actual SQL using `node-sql-parser`
- Analyzes Abstract Syntax Tree (AST) for violations:
  - Multiple statements (stacked queries)
  - Blocked operations (DROP, DELETE, TRUNCATE, etc.)
  - Excessive nesting depth
  - Dangerous functions (xp_cmdshell, sp_executesql)

**When to use**:
- Authentication endpoints
- Admin panels
- Database management interfaces
- Payment processing

---

## Installation

```bash
npm install crypto fs path
# Optional: For AST parsing
npm install node-sql-parser
```

**Basic setup**:
```javascript
const SQLInjectionDetector = require('./checks/sqlinjection.js');
const detector = new SQLInjectionDetector();
```

**With configuration file**:
```javascript
const detector = new SQLInjectionDetector('./config/sql_injection.config.js');
```

---

## Quick Start

### Express.js Middleware

```javascript
const express = require('express');
const SQLInjectionDetector = require('./checks/sqlinjection.js');

const app = express();
const detector = new SQLInjectionDetector();

app.use(express.json());
app.use(detector.middleware());

app.post('/api/login', (req, res) => {
  // Request automatically checked
  // Malicious inputs blocked before reaching here
  res.json({ success: true });
});

app.listen(3000);
```

### Standalone Usage

```javascript
const detector = new SQLInjectionDetector();

// Single check
const result = detector.check("' OR '1'='1");
console.log(result.blocked); // true

// Batch check
const results = detector.checkBatch([
  "john@example.com",
  "admin'--",
  "normal text"
]);
```

---

## Detection Pipelines

### Pipeline 1: Bloom Filter Only

**Use case**: High-traffic, low-risk endpoints (public search, content browsing)

```javascript
const detector = new SQLInjectionDetector();
detector.config.mode = "bloom";
detector.config.heuristic.enabled = false;
detector.config.astParser.enabled = false;
```

**Performance**: ~0.01ms per check  
**Accuracy**: High recall, moderate precision  
**Trade-off**: Fastest, but may have false positives

### Pipeline 2: Bloom + Heuristic (Default)

**Use case**: Most application endpoints

```javascript
const detector = new SQLInjectionDetector();
// Default mode: "bloom+heuristic"
```

**Performance**: ~0.1-0.5ms per check  
**Accuracy**: High recall and precision  
**Trade-off**: Excellent balance

### Pipeline 3: Bloom + Heuristic + AST

**Use case**: Critical security endpoints

```javascript
const detector = new SQLInjectionDetector();
detector.config.mode = "bloom+heuristic+ast";
detector.config.astParser.enabled = true;
```

**Performance**: ~1-5ms per check  
**Accuracy**: Maximum security  
**Trade-off**: Highest accuracy, slower

---

## Configuration

### Complete Configuration Object

```javascript
{
  mode: "bloom+heuristic", // or "bloom+heuristic+ast"

  bloomFilter: {
    enabled: true,
    size: 10000,              // Bit array size
    hashFunctions: 3,         // Number of hash functions
    whitelist: []             // Additional safe tokens
  },

  heuristic: {
    enabled: true,
    threshold: 5,             // Score threshold for blocking
    weights: {
      sqlKeywords: 4,
      commentPatterns: 3,
      quoteAnomalies: 3,
      unionAttacks: 6,
      stackedQueries: 5,
      encodedChars: 3,
      hexPatterns: 4
    }
  },

  astParser: {
    enabled: false,
    sqlDialect: "mysql",      // mysql, postgresql, sqlite, etc.
    maxNestingDepth: 3,
    blockedOperations: [
      "DROP", "DELETE", "TRUNCATE", 
      "ALTER", "EXEC", "EXECUTE"
    ],
    allowMultipleStatements: false
  },

  performance: {
    enableCaching: true,
    cacheSize: 1000,          // LRU cache size
    timeout: 100              // Max execution time (ms)
  },

  onDetection: {
    action: "block",          // "block", "sanitize", "log"
    sanitizationStrategy: "escape", // "escape", "remove", "encode"
    returnError: true,
    customErrorMessage: "Potential SQL injection detected"
  },

  routes: {
    "/api/auth/login": {
      mode: "bloom+heuristic+ast",
      heuristic: { threshold: 3 }
    },
    "/api/public/search": {
      mode: "bloom+heuristic",
      heuristic: { threshold: 7 }
    }
  },

  logging: {
    logAllChecks: false,
    logBlockedOnly: true,
    logSlowQueries: true,
    slowQueryThreshold: 50    // ms
  },

  development: {
    disableInDev: true,
    envVariable: "NODE_ENV",
    devEnvironments: ["development", "dev", "local"]
  }
}
```

### Configuration from File

Create `config/sql_injection.config.js`:

```javascript
module.exports = {
  mode: "bloom+heuristic+ast",
  
  heuristic: {
    threshold: 3,
    weights: {
      sqlKeywords: 5,
      unionAttacks: 8
    }
  },

  routes: {
    "/api/auth/*": {
      mode: "bloom+heuristic+ast",
      heuristic: { threshold: 2 }
    }
  }
};
```

Load it:
```javascript
const detector = new SQLInjectionDetector('./config/sql_injection.config.js');
```

---

## API Reference

### Constructor

```javascript
new SQLInjectionDetector(configPath)
```

**Parameters**:
- `configPath` (string, optional): Path to configuration file

**Returns**: SQLInjectionDetector instance

### Methods

#### `detect(input)`

Primary detection method.

```javascript
const result = detector.detect("' OR '1'='1");
```

**Parameters**:
- `input` (string): User input to check

**Returns**:
```javascript
{
  input: "' OR '1'='1",
  blocked: true,
  mode: "bloom+heuristic",
  pipeline: [
    {
      stage: "Bloom Filter",
      passed: false,
      suspiciousRatio: 0.8,
      suspiciousTokens: 4,
      totalTokens: 5
    },
    {
      stage: "Heuristic Matching",
      passed: false,
      score: 12,
      threshold: 5,
      detections: [
        { type: "Classic Injection Pattern", weight: 6 },
        { type: "Quote Anomalies", weight: 3 },
        { type: "SQL Keywords", weight: 4 }
      ]
    }
  ],
  reason: "Heuristic threshold exceeded",
  executionTime: 0.245
}
```

#### `check(input)`

Alias for `detect()`.

```javascript
const result = detector.check(input);
```

#### `checkBatch(inputs)`

Check multiple inputs at once.

```javascript
const results = detector.checkBatch([
  "user@example.com",
  "admin'--",
  "SELECT * FROM users"
]);
```

**Returns**: Array of detection results

#### `middleware()`

Express/Koa middleware generator.

```javascript
app.use(detector.middleware());
```

**Behavior**:
- Checks `req.body`, `req.query`, `req.params`
- Blocks request with 403 if malicious
- Logs detections based on config
- Calls `next()` for safe requests

#### `sanitize(input)`

Sanitize input based on strategy.

```javascript
const safe = detector.sanitize("test'value");
// With escape strategy: "test''value"
```

**Strategies**:
- `escape`: Escapes quotes and special chars
- `remove`: Removes dangerous patterns
- `encode`: Base64 encodes input

#### `getStats()`

Get detector statistics.

```javascript
const stats = detector.getStats();
```

**Returns**:
```javascript
{
  cacheSize: 150,
  maxCacheSize: 1000,
  bloomFilterSize: 10000,
  mode: "bloom+heuristic",
  config: { /* full config */ }
}
```

#### `clearCache()`

Clear detection cache.

```javascript
detector.clearCache();
```

---

## Examples

### Example 1: Basic Protection

```javascript
const express = require('express');
const SQLInjectionDetector = require('./checks/sqlinjection.js');

const app = express();
const detector = new SQLInjectionDetector();

app.use(express.json());
app.use(detector.middleware());

app.post('/api/users', (req, res) => {
  const { username, email } = req.body;
  // Safe to use - already validated
  res.json({ success: true });
});

app.listen(3000);
```

### Example 2: Route-Specific Configuration

```javascript
const detector = new SQLInjectionDetector();

// Strict checking for auth
detector.config.routes['/api/auth/login'] = {
  mode: "bloom+heuristic+ast",
  heuristic: { threshold: 2 }
};

// Lenient for public search
detector.config.routes['/api/search'] = {
  mode: "bloom+heuristic",
  heuristic: { threshold: 8 }
};

app.use(detector.middleware());
```

### Example 3: Custom Error Handling

```javascript
const detector = new SQLInjectionDetector();
detector.config.onDetection.returnError = true;
detector.config.onDetection.customErrorMessage = "Invalid input detected";

app.use(detector.middleware());

// Returns:
// {
//   error: "Invalid input detected",
//   field: "username",
//   details: { /* detection details */ }
// }
```

### Example 4: Sanitization Instead of Blocking

```javascript
const detector = new SQLInjectionDetector();
detector.config.onDetection.action = "sanitize";
detector.config.onDetection.sanitizationStrategy = "escape";

app.use(detector.middleware());

// Input: "test'value"
// After middleware: "test''value"
```

### Example 5: Manual Checking

```javascript
const detector = new SQLInjectionDetector();

app.post('/api/custom', (req, res) => {
  const { search } = req.body;
  
  const result = detector.check(search);
  
  if (result.blocked) {
    console.error('SQL injection attempt:', result);
    return res.status(400).json({ 
      error: 'Invalid search query' 
    });
  }
  
  // Proceed with search
  res.json({ results: [] });
});
```

### Example 6: Batch Validation

```javascript
const detector = new SQLInjectionDetector();

app.post('/api/import', (req, res) => {
  const { records } = req.body; // Array of user inputs
  
  const values = records.map(r => r.value);
  const results = detector.checkBatch(values);
  
  const blocked = results.filter(r => r.blocked);
  
  if (blocked.length > 0) {
    return res.status(400).json({
      error: 'Some records contain invalid data',
      count: blocked.length
    });
  }
  
  // Process records
  res.json({ success: true });
});
```

### Example 7: AST Deep Inspection

```javascript
const detector = new SQLInjectionDetector();
detector.config.mode = "bloom+heuristic+ast";
detector.config.astParser.enabled = true;
detector.config.astParser.blockedOperations = [
  "DROP", "DELETE", "TRUNCATE", "ALTER"
];

app.post('/api/admin/query', (req, res) => {
  const { query } = req.body;
  
  const result = detector.check(query);
  
  if (result.blocked) {
    const astStage = result.pipeline.find(p => p.stage === "AST Parser");
    if (astStage && astStage.violations) {
      return res.status(403).json({
        error: "Query contains blocked operations",
        violations: astStage.violations
      });
    }
  }
  
  // Execute query
});
```

### Example 8: Performance Monitoring

```javascript
const detector = new SQLInjectionDetector();
detector.config.logging.logSlowQueries = true;
detector.config.logging.slowQueryThreshold = 10; // 10ms

setInterval(() => {
  const stats = detector.getStats();
  console.log('Cache utilization:', 
    `${stats.cacheSize}/${stats.maxCacheSize}`);
}, 60000);
```

---

## Performance


### Optimization Tips

1. **Enable Caching**
```javascript
detector.config.performance.enableCaching = true;
detector.config.performance.cacheSize = 5000; // Increase for high traffic
```

2. **Adjust Bloom Filter Size**
```javascript
detector.config.bloomFilter.size = 20000; // Reduce false positives
```

3. **Use Route-Specific Pipelines**
```javascript
// Fast pipeline for public endpoints
detector.config.routes['/api/public/*'] = {
  mode: "bloom+heuristic",
  heuristic: { threshold: 7 }
};

// Strict pipeline for sensitive endpoints
detector.config.routes['/api/admin/*'] = {
  mode: "bloom+heuristic+ast"
};
```

4. **Disable in Development**
```javascript
detector.config.development.disableInDev = true;
```

### Memory Usage

- Base detector: ~2MB
- Bloom filter: ~1.25MB (10,000 size)
- Cache (1000 entries): ~0.5MB
- AST parser: ~10MB (when loaded)

**Total**: ~3.75MB without AST, ~13.75MB with AST

---

## Testing

### Run Tests

```bash
npm test
# or
npx jest middleware/test/sql_injection.test.js
```

### Test Coverage

- 74 test cases
- All detection patterns
- Edge cases (null, unicode, long input)
- Performance benchmarks
- Real-world attack vectors

### Write Custom Tests

```javascript
const SQLInjectionDetector = require('./checks/sqlinjection.js');

describe('Custom Tests', () => {
  let detector;

  beforeEach(() => {
    detector = new SQLInjectionDetector();
  });

  test('should block my custom pattern', () => {
    const result = detector.check("my custom attack");
    expect(result.blocked).toBe(true);
  });
});
```

---

## Advanced Topics

### Custom Whitelist

Add domain-specific safe terms:

```javascript
const detector = new SQLInjectionDetector();
detector.config.bloomFilter.whitelist = [
  "username", "email", "profile", "settings"
];
detector._initializeBloomFilter(); // Reinitialize
```

### Dynamic Threshold Adjustment

Adjust threshold based on user reputation:

```javascript
app.post('/api/comment', (req, res) => {
  const user = req.user;
  const originalThreshold = detector.config.heuristic.threshold;
  
  // Trusted users get higher threshold
  if (user.reputation > 100) {
    detector.config.heuristic.threshold = 8;
  }
  
  detector.clearCache(); // Force re-evaluation
  const result = detector.check(req.body.comment);
  
  detector.config.heuristic.threshold = originalThreshold;
  
  if (result.blocked) {
    return res.status(400).json({ error: 'Invalid comment' });
  }
  
  // Save comment
});
```

### Custom Detection Rules

Extend the heuristic checker:

```javascript
class CustomDetector extends SQLInjectionDetector {
  _heuristicCheck(input) {
    const result = super._heuristicCheck(input);
    
    // Add custom rule
    if (/my-dangerous-pattern/.test(input)) {
      result.score += 10;
      result.detections.push({
        type: "Custom Pattern",
        weight: 10
      });
    }
    
    result.passed = result.score < this.config.heuristic.threshold;
    return result;
  }
}
```

---

## Security Considerations

### What This Detector Catches

✅ Classic SQL injection (`' OR '1'='1`)  
✅ UNION-based attacks  
✅ Comment-based attacks (`admin'--`)  
✅ Stacked queries (`'; DROP TABLE`)  
✅ Time-based blind injection  
✅ Boolean-based blind injection  
✅ Error-based injection  
✅ Encoded/obfuscated attacks  
✅ Second-order injection patterns  

### What This Detector Does NOT Replace

❌ Parameterized queries (still use these!)  
❌ ORM validation  
❌ Input sanitization at database layer  
❌ Proper access controls  
❌ Rate limiting  

### Best Practices

1. **Use parameterized queries** as primary defense
2. **Use this detector** as additional layer
3. **Log all blocked attempts** for security monitoring
4. **Adjust thresholds** based on your traffic patterns
5. **Test thoroughly** with your specific use cases
6. **Monitor false positives** and tune configuration
7. **Use AST parsing** for admin/auth endpoints

---

## Troubleshooting

### High False Positive Rate

```javascript
// Increase threshold
detector.config.heuristic.threshold = 8;

// Or adjust weights
detector.config.heuristic.weights.sqlKeywords = 2; // Down from 4
```

### Performance Issues

```javascript
// Increase cache size
detector.config.performance.cacheSize = 10000;

// Disable AST for non-critical endpoints
detector.config.astParser.enabled = false;

// Use bloom-only for high-traffic routes
detector.config.routes['/api/public/*'] = { mode: "bloom" };
```

### AST Parser Not Loading

```bash
# Install the optional dependency
npm install node-sql-parser

# Verify installation
node -e "require('node-sql-parser')"
```

---

## Thank you!