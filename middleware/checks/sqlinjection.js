const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

/**
 * SQL Injection Detection System
 * Supports two pipelines:
 * 1. Bloom Filter + Heuristic Matching
 * 2. Bloom Filter + Heuristic Matching + AST Parser
 */
class SQLInjectionDetector {
  constructor(configPath = null) {
    // Load config from file if provided, otherwise use defaults
    let config = {};

    if (configPath) {
      try {
        const configFile = path.resolve(configPath);
        // Clear require cache to allow hot reload
        delete require.cache[require.resolve(configFile)];
        config = require(configFile);
      } catch (e) {
        // Silently fall back to defaults
      }
    }

    this.config = {
      mode: config.mode || "bloom+heuristic",

      bloomFilter: {
        enabled: config.bloomFilter?.enabled !== false,
        size: config.bloomFilter?.size || 10000,
        hashFunctions: config.bloomFilter?.hashFunctions || 3,
        whitelist: config.bloomFilter?.whitelist || [],
      },

      heuristic: {
        enabled: config.heuristic?.enabled !== false,
        threshold: config.heuristic?.threshold || 3, // Aggressive default - prioritize detection
        weights: {
          sqlKeywords: config.heuristic?.weights?.sqlKeywords || 4,
          commentPatterns: config.heuristic?.weights?.commentPatterns || 3,
          quoteAnomalies: config.heuristic?.weights?.quoteAnomalies || 3,
          unionAttacks: config.heuristic?.weights?.unionAttacks || 6,
          stackedQueries: config.heuristic?.weights?.stackedQueries || 5,
          encodedChars: config.heuristic?.weights?.encodedChars || 3,
          hexPatterns: config.heuristic?.weights?.hexPatterns || 4,
        },
      },

      astParser: {
        enabled: config.astParser?.enabled || false,
        sqlDialect: config.astParser?.sqlDialect || "mysql",
        maxNestingDepth: config.astParser?.maxNestingDepth || 3,
        blockedOperations: config.astParser?.blockedOperations || [
          "DROP",
          "DELETE",
          "TRUNCATE",
          "ALTER",
          "EXEC",
          "EXECUTE",
        ],
        allowMultipleStatements:
          config.astParser?.allowMultipleStatements || false,
      },

      performance: {
        enableCaching: config.performance?.enableCaching !== false,
        cacheSize: config.performance?.cacheSize || 1000,
        timeout: config.performance?.timeout || 100,
      },

      onDetection: {
        action: config.onDetection?.action || "block",
        sanitizationStrategy:
          config.onDetection?.sanitizationStrategy || "escape",
        returnError: config.onDetection?.returnError !== false,
        customErrorMessage:
          config.onDetection?.customErrorMessage ||
          "Potential SQL injection detected",
      },

      routes: config.routes || {},
      logging: config.logging || {},
      development: config.development || {},
    };

    // Initialize Bloom Filter
    this.bloomFilterBitArray = new Array(this.config.bloomFilter.size).fill(0);
    this._initializeBloomFilter();

    // Cache for performance
    this.cache = new Map();

    // Load SQL parser if AST is enabled
    // In sqlinjection.js, temporarily modify the constructor:
    if (
      this.config.mode === "bloom+heuristic+ast" ||
      this.config.astParser.enabled
    ) {
      try {
        this.sqlParser = require("node-sql-parser");
        this.parser = new this.sqlParser.Parser();
        console.log("✓ AST Parser loaded successfully");
      } catch (e) {
        console.error("✗ AST Parser failed to load:", e.message);
        console.error("Error details:", e);
        this.config.astParser.enabled = false;
      }
    }
  }

  /**
   * Initialize Bloom Filter with whitelist patterns
   */
  _initializeBloomFilter() {
    const defaultWhitelist = [
      "select",
      "from",
      "where",
      "and",
      "or",
      "order",
      "by",
      "group",
      "limit",
      "offset",
      "join",
      "inner",
      "left",
      "right",
    ];

    const whitelist = [
      ...defaultWhitelist,
      ...this.config.bloomFilter.whitelist,
    ];

    whitelist.forEach((pattern) => {
      this._addToBloomFilter(pattern.toLowerCase());
    });
  }

  /**
   * Add item to Bloom Filter
   */
  _addToBloomFilter(item) {
    for (let i = 0; i < this.config.bloomFilter.hashFunctions; i++) {
      const hash = this._hash(item, i);
      this.bloomFilterBitArray[hash] = 1;
    }
  }

  /**
   * Check if item exists in Bloom Filter
   */
  _checkBloomFilter(item) {
    for (let i = 0; i < this.config.bloomFilter.hashFunctions; i++) {
      const hash = this._hash(item, i);
      if (this.bloomFilterBitArray[hash] === 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Hash function for Bloom Filter
   */
  _hash(item, seed) {
    const hash = crypto
      .createHash("md5")
      .update(item + seed)
      .digest("hex");
    return parseInt(hash.substring(0, 8), 16) % this.config.bloomFilter.size;
  }

  /**
   * Bloom Filter Check
   */
  _bloomFilterCheck(input) {
    // Handle null/undefined/non-string
    if (!input || typeof input !== "string") {
      return {
        passed: true,
        suspiciousRatio: 0,
        suspiciousTokens: 0,
        totalTokens: 0,
      };
    }

    const normalized = input.toLowerCase().trim();
    const tokens = normalized.split(/\s+/);
    let suspiciousTokens = 0;

    tokens.forEach((token) => {
      if (!this._checkBloomFilter(token)) {
        suspiciousTokens++;
      }
    });

    const suspiciousRatio = suspiciousTokens / tokens.length;

    return {
      passed: suspiciousRatio < 0.3,
      suspiciousRatio,
      suspiciousTokens,
      totalTokens: tokens.length,
    };
  }

  /**
   * Heuristic Pattern Matching with Scoring
   */
  _heuristicCheck(input) {
    // Handle null/undefined/non-string
    if (!input || typeof input !== "string") {
      return {
        passed: true,
        score: 0,
        threshold: this.config.heuristic.threshold,
        detections: [],
      };
    }

    let score = 0;
    const detections = [];
    const weights = this.config.heuristic.weights;

    // --- 1. SQL Keywords Detection (only dangerous context) ---
    const sqlKeywords =
      /\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|onerror|onload)\b/gi;
    const dangerousContext = /['";#]|--|\/\*/;
    const keywordMatches = (input.match(sqlKeywords) || []).filter((k) =>
      dangerousContext.test(input)
    );
    if (keywordMatches.length > 0) {
      score += weights.sqlKeywords * keywordMatches.length;
      detections.push({
        type: "SQL Keywords",
        matches: keywordMatches,
        weight: weights.sqlKeywords,
      });
    }

    // --- 2. Comment Patterns ---
    const commentPatterns = /(--|\/\*|\*\/|#)/g;
    const commentMatches = input.match(commentPatterns);
    if (commentMatches) {
      score += weights.commentPatterns * commentMatches.length;
      detections.push({
        type: "Comment Patterns",
        matches: commentMatches,
        weight: weights.commentPatterns,
      });
    }

    // --- 3. Quote Anomalies ---
    const singleQuotes = (input.match(/'/g) || []).length;
    const doubleQuotes = (input.match(/"/g) || []).length;
    if (singleQuotes % 2 !== 0 || doubleQuotes % 2 !== 0) {
      score += weights.quoteAnomalies;
      detections.push({
        type: "Unbalanced Quotes",
        weight: weights.quoteAnomalies,
      });
    }

    // --- 4. Classic SQL Injection Patterns ---
    const classicPatterns = [
      /'?\s*or\s+'?1'?\s*=\s*'?1/gi,
      /'?\s*and\s+'?1'?\s*=\s*'?1/gi,
      /'?\s*or\s+'?"?\w+"?\s*=\s*'?"?\w+"?/gi,
      /'\s*--/gi,
      /'\s*#/gi,
      /'\s*\/\*/gi,
      /'\s*;\s*/gi,
      /--\s*$/gi,
      /#\s*$/gi,
      /'\s*\|\|/gi,
      /\bor\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/gi,
      /\band\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/gi,
    ];

    let classicMatchCount = 0;
    for (const pattern of classicPatterns) {
      if (pattern.test(input)) classicMatchCount++;
    }
    classicMatchCount = Math.min(classicMatchCount, 2); // cap to avoid score explosion
    if (classicMatchCount > 0) {
      score += weights.unionAttacks * classicMatchCount;
      detections.push({
        type: "Classic Injection Pattern",
        weight: weights.unionAttacks * classicMatchCount,
        matches: classicMatchCount,
      });
    }

    // --- 5. UNION Attacks ---
    const unionPattern = /union\s+(all\s+)?select/gi;
    if (unionPattern.test(input)) {
      score += weights.unionAttacks;
      detections.push({ type: "UNION Attack", weight: weights.unionAttacks });
    }

    // --- 6. Stacked Queries ---
    const stackedQueries = /;\s*(select|insert|update|delete|drop|create)/gi;
    if (stackedQueries.test(input)) {
      score += weights.stackedQueries;
      detections.push({
        type: "Stacked Queries",
        weight: weights.stackedQueries,
      });
    }

    // --- 7. Encoded Characters ---
    const encodedChars = /(%27|%23|%2d|%2f|%3d|\\x27|\\x23)/gi;
    const encodedMatches = input.match(encodedChars);
    if (encodedMatches) {
      score += weights.encodedChars * encodedMatches.length;
      detections.push({
        type: "Encoded Characters",
        matches: encodedMatches,
        weight: weights.encodedChars,
      });
    }

    // --- 8. Hex/Char Patterns ---
    const hexPattern = /(0x[0-9a-f]{2,}|char\s*\(|ascii\s*\()/gi;
    if (hexPattern.test(input)) {
      score += weights.hexPatterns;
      detections.push({
        type: "Hex/Char Patterns",
        weight: weights.hexPatterns,
      });
    }

    // --- 9. Advanced Attack Patterns ---
    const advancedPatterns = [
      /waitfor\s+delay/gi,
      /benchmark\s*\(/gi,
      /sleep\s*\(/gi,
      /pg_sleep\s*\(/gi,
      /xp_cmdshell/gi,
      /into\s+(out|dump)file/gi,
      /load_file\s*\(/gi,
      /information_schema/gi,
      /substring\s*\(/gi,
      /extractvalue\s*\(/gi,
      /updatexml\s*\(/gi,
      /convert\s*\(/gi,
      /cast\s*\(/gi,
      /concat\s*\(/gi,
    ];
    for (const pattern of advancedPatterns) {
      if (pattern.test(input)) {
        score += weights.sqlKeywords * 2;
        detections.push({
          type: "Advanced Attack Pattern",
          weight: weights.sqlKeywords * 2,
        });
        break;
      }
    }

    // --- 10. Suspicious combinations (refined) ---
    if (
      /'/.test(input) &&
      /\b(or|and|union|select)\b/gi.test(input) &&
      input.indexOf("'") < input.search(/\b(or|and|union|select)\b/i)
    ) {
      score += 2;
      detections.push({ type: "Suspicious Combination", weight: 2 });
    }

    // --- 11. False Positive Reduction ---
    const hasSqlKeywords = /\b(select|update|delete|drop)\b/gi.test(input);
    const hasNoQuotes = !/['"]/.test(input);
    const hasNoDangerousChars = !/[;#]|--|\*\//.test(input);
    const isLikelyNaturalLanguage =
      /\b(I|want|to|please|this|that|my|me|a)\b/gi.test(input);

    if (
      hasSqlKeywords &&
      hasNoQuotes &&
      hasNoDangerousChars &&
      isLikelyNaturalLanguage
    ) {
      score = Math.max(0, score - 3);
      detections.push({ type: "Natural Language Adjustment", weight: -3 });
    }

    // WP-specific adjustment
    if (
      /\b(post_type|post_status|post_name|meta_key)\b/i.test(input) &&
      !/['"]/.test(input)
    ) {
      score = Math.max(0, score - 4);
      detections.push({ type: "WP Query Adjustment", weight: -4 });
    }

    // --- 12. Boolean Blind Injection Patterns ---
    const booleanBlindPatterns = [
      /'\s*and\s+'?1'?\s*=\s*'?[12]/gi,
      /'\s*and\s+substring/gi,
      /'\s*and\s+ascii/gi,
      /'\s*and\s+\w+\s*=\s*\w+\s*--/gi,
    ];
    for (const pattern of booleanBlindPatterns) {
      if (pattern.test(input)) {
        score += weights.sqlKeywords * 2;
        detections.push({
          type: "Boolean-Based Blind Injection",
          weight: weights.sqlKeywords * 2,
        });
        break;
      }
    }

    // --- 13. Dynamic Threshold (optional) ---
    let threshold = this.config.heuristic.threshold;
    if (/\b(post_type|post_status|post_name)\b/i.test(input)) threshold += 2;

    return {
      passed: score < threshold,
      score,
      threshold,
      detections,
    };
  }

  /**
   * AST Parser Check
   */
  _astParserCheck(input) {
    if (!this.parser) {
      return {
        passed: true,
        error: "AST Parser not available",
        skipped: true,
      };
    }

    try {
      const ast = this.parser.astify(input, {
        database: this.config.astParser.sqlDialect,
      });

      const violations = [];

      if (
        Array.isArray(ast) &&
        ast.length > 1 &&
        !this.config.astParser.allowMultipleStatements
      ) {
        violations.push({ type: "Multiple Statements", count: ast.length });
      }

      const statements = Array.isArray(ast) ? ast : [ast];

      statements.forEach((stmt, idx) => {
        if (
          stmt.type &&
          this.config.astParser.blockedOperations.includes(
            stmt.type.toUpperCase()
          )
        ) {
          violations.push({
            type: "Blocked Operation",
            operation: stmt.type,
            statementIndex: idx,
          });
        }

        const depth = this._getASTDepth(stmt);
        if (depth > this.config.astParser.maxNestingDepth) {
          violations.push({
            type: "Excessive Nesting",
            depth,
            maxAllowed: this.config.astParser.maxNestingDepth,
          });
        }

        const dangerousFunctions = [
          "exec",
          "execute",
          "sp_executesql",
          "xp_cmdshell",
        ];
        const functionsUsed = this._extractFunctions(stmt);
        const dangerous = functionsUsed.filter((fn) =>
          dangerousFunctions.some((df) => fn.toLowerCase().includes(df))
        );

        if (dangerous.length > 0) {
          violations.push({
            type: "Dangerous Functions",
            functions: dangerous,
          });
        }
      });

      return {
        passed: violations.length === 0,
        violations,
        ast: ast,
      };
    } catch (e) {
      const looksLikeSQL =
        /\b(select|from|where|union|insert|update|delete)\b/gi.test(input);
      const suspiciousKeywords =
        /\b(select|union|insert|update|delete|drop|create|alter|truncate|exec)\b/i;
      const isSuspicious = suspiciousKeywords.test(input);

      return {
        passed: !isSuspicious, // if suspicious, consider it failing
        parseError: true,
        looksLikeSQL: isSuspicious,
        error: e.message,
        skipped: false,
        reason: isSuspicious
          ? "AST parseError + SQL keywords detected"
          : "AST parseError",
      };
    }
  }

  /**
   * Get AST depth (recursive)
   */
  _getASTDepth(node, depth = 0) {
    if (!node || typeof node !== "object") {
      return depth;
    }

    let maxDepth = depth;

    for (const key in node) {
      if (node[key] && typeof node[key] === "object") {
        const childDepth = this._getASTDepth(node[key], depth + 1);
        maxDepth = Math.max(maxDepth, childDepth);
      }
    }

    return maxDepth;
  }

  /**
   * Extract function names from AST
   */
  _extractFunctions(node, functions = []) {
    if (!node || typeof node !== "object") {
      return functions;
    }

    if (node.type === "function" && node.name) {
      functions.push(node.name);
    }

    for (const key in node) {
      if (node[key] && typeof node[key] === "object") {
        this._extractFunctions(node[key], functions);
      }
    }

    return functions;
  }

  /**
   * Main Detection Pipeline
   */
  detect(input) {
    const startTime = Date.now();

    // Handle non-string inputs early
    if (!input || typeof input !== "string") {
      return {
        input,
        blocked: false,
        mode: this.config.mode,
        pipeline: [],
        executionTime: 0,
      };
    }

    // Decode percent-encoded payloads once (safe decode)
    let decodedInput;
    try {
      decodedInput = decodeURIComponent(input);
    } catch (e) {
      // malformed percent-encoding -> fallback to original
      decodedInput = input;
    }
    // normalized input used for heuristic / quick checks
    const checkInput = decodedInput || input;

    if (this.config.performance.enableCaching) {
      const cached = this.cache.get(input);
      if (cached) {
        return { ...cached, cached: true };
      }
    }

    const result = {
      input,
      blocked: false,
      mode: this.config.mode,
      pipeline: [],
      executionTime: 0,
    };

    if (this.config.bloomFilter.enabled) {
      const bloomResult = this._bloomFilterCheck(checkInput);
      result.pipeline.push({ stage: "Bloom Filter", ...bloomResult });

      if (bloomResult.passed && bloomResult.suspiciousRatio < 0.1) {
        result.executionTime = Date.now() - startTime;
        this._updateCache(input, result);
        return result;
      }
    }

    let heuristicResult = null;
    if (this.config.heuristic.enabled) {
      heuristicResult = this._heuristicCheck(checkInput);
      result.pipeline.push({ stage: "Heuristic Matching", ...heuristicResult });

      if (!heuristicResult.passed) {
        // Only block if heuristic has multiple suspicious types or combined weight > threshold
        const dets = heuristicResult.detections || [];
        const suspiciousTypes = new Set(dets.map((d) => d.type));
        const combinedWeight = dets.reduce(
          (sum, d) => sum + (d.weight || 0),
          0
        );

        const hasMultipleFeatures =
          suspiciousTypes.size > 1 ||
          combinedWeight > (this.config.heuristic.threshold || 3);

        if (hasMultipleFeatures) {
          result.blocked = true;
          result.reason = "Heuristic threshold exceeded (strong)";
          result.executionTime = Date.now() - startTime;
          this._updateCache(input, result);
          return result;
        } else {
          // Weak heuristic only -> do not block, mark for logging
          result.heuristicWarning = true;
        }
      }
    }

    if (
      this.config.mode === "bloom+heuristic+ast" &&
      this.config.astParser.enabled
    ) {
      // Use decoded input for AST attempts as well (helps with encoded payloads)
      const astResult = this._astParserCheck(checkInput);
      result.pipeline.push({ stage: "AST Parser", ...astResult });

      // Improved quick SQL regex (higher-confidence patterns)
      const quickSqlRegex = new RegExp(
        [
          "\\bor\\s+1\\s*=\\s*1\\b", // tautology
          "\\b'\\s*or\\s*'[^']+'\\s*=\\s*'[^']+'\\b", // tautology with quotes
          "\\bunion\\b\\s*(all\\s*)?\\bselect\\b", // union select
          ";\\s*(select\\s+.+?\\s+from|insert\\s+into|update\\s+\\w+|delete\\s+from|drop\\s+table|create\\s+table|alter\\s+table)\\b", // stacked queries with context
          "\\bchar\\s*\\(", // char(
          "\\bconcat\\s*\\(", // concat(
          "\\bbenchmark\\s*\\(", // benchmark(
          "\\bsleep\\s*\\(", // sleep(
          "\\bpg_sleep\\s*\\(", // pg_sleep(
          "0x[0-9a-f]{2,}", // hex literals
          "(%27|%3d|%23|%2d|%2b)", // percent-encoded tokens (less aggressive)
          "(--\\s|/\\*|\\*/|#\\s)", // comments with optional trailing space
          "\\bexec\\b|\\bxp_cmdshell\\b|\\bload_file\\b|\\binformation_schema\\b", // dangerous functions
        ].join("|"),
        "i"
      );

      // If AST parse failed, only force-block when there's a stronger signal:
      // quickMatch (high-confidence) OR (parser thinks it looks like SQL AND heuristic had hits)
      if (astResult.parseError) {
        const looksLikeSQL = !!astResult.looksLikeSQL;

        const heuristicScore = heuristicResult ? heuristicResult.score || 0 : 0;
        const heuristicSuspicious = heuristicScore > 0;

        const quickMatch = quickSqlRegex.test(checkInput);

        const shouldForceBlock =
          quickMatch || (looksLikeSQL && heuristicSuspicious);

        if (shouldForceBlock) {
          result.blocked = true;
          result.reason = "AST parseError + suspicious pattern";
          result.executionTime = Date.now() - startTime;
          this._updateCache(input, result);
          return result;
        } else {
          // Do not block on parseError alone; record for debugging/analysis
          result.parseErrorButAllowed = true;
        }
      }

      // If AST returned definite violations (and it wasn't a plain parseError), block as before
      if (!astResult.passed && !astResult.skipped && !astResult.parseError) {
        result.blocked = true;
        result.reason = "AST violations detected";
        result.executionTime = Date.now() - startTime;
        this._updateCache(input, result);
        return result;
      }
    }

    result.executionTime = Date.now() - startTime;
    this._updateCache(input, result);
    return result;
  }

  /**
   * Update cache with LRU policy
   */
  _updateCache(input, result) {
    if (!this.config.performance.enableCaching) return;

    if (this.cache.size >= this.config.performance.cacheSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }

    this.cache.set(input, result);
  }

  /**
   * Sanitize input based on strategy
   */
  sanitize(input) {
    if (!input || typeof input !== "string") {
      return input;
    }

    const strategy = this.config.onDetection.sanitizationStrategy;

    switch (strategy) {
      case "escape":
        return input
          .replace(/'/g, "''")
          .replace(/"/g, '""')
          .replace(/\\/g, "\\\\")
          .replace(/;/g, "\\;");

      case "remove":
        return input.replace(
          /('|"|--|\/\*|\*\/|;|\bor\b|\band\b|\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b)/gi,
          ""
        );

      case "encode":
        return Buffer.from(input).toString("base64");

      default:
        return input;
    }
  }

  /**
   * Get route-specific config or use default
   */
  _getRouteConfig(route) {
    if (this.config.routes && this.config.routes[route]) {
      const routeConfig = this.config.routes[route];
      return {
        ...this.config,
        mode: routeConfig.mode || this.config.mode,
        heuristic: {
          ...this.config.heuristic,
          ...(routeConfig.heuristic || {}),
        },
        astParser: {
          ...this.config.astParser,
          ...(routeConfig.astParser || {}),
        },
      };
    }
    return this.config;
  }

  /**
   * Middleware for Express/Koa
   */
  middleware() {
    return (req, res, next) => {
      try {
        if (this.config.development?.disableInDev) {
          const env = process.env[this.config.development.envVariable] || "";
          if (
            this.config.development.devEnvironments.includes(env.toLowerCase())
          ) {
            return next();
          }
        }

        const route = req.route?.path || req.path || req.url;
        const originalConfig = this.config;
        this.config = this._getRouteConfig(route);

        const inputs = this._extractInputs(req);

        for (const [field, value] of Object.entries(inputs)) {
          if (typeof value === "string" && value.length > 0) {
            const result = this.detect(value);

            if (
              this.config.logging?.logAllChecks ||
              (this.config.logging?.logBlockedOnly && result.blocked)
            ) {
              console.log("[SQL Injection Check]", {
                route,
                field,
                blocked: result.blocked,
                executionTime: result.executionTime,
              });
            }

            if (
              this.config.logging?.logSlowQueries &&
              result.executionTime >
                (this.config.logging?.slowQueryThreshold || 50)
            ) {
              console.warn("[Slow SQL Check]", {
                route,
                field,
                executionTime: result.executionTime,
              });
            }

            if (result.blocked) {
              if (this.config.onDetection.action === "block") {
                this.config = originalConfig;

                const errorResponse = {
                  error: this.config.onDetection.customErrorMessage,
                  field,
                };

                if (this.config.onDetection.returnError) {
                  errorResponse.details = result;
                }

                return res.status(403).json(errorResponse);
              } else if (this.config.onDetection.action === "sanitize") {
                const sanitized = this.sanitize(value);
                if (req.body[field]) req.body[field] = sanitized;
                if (req.query[field]) req.query[field] = sanitized;
                if (req.params[field]) req.params[field] = sanitized;
              }
            }
          }
        }

        this.config = originalConfig;
        next();
      } catch (error) {
        console.error("SQL Injection Detection Error:", error);
        next();
      }
    };
  }

  /**
   * Extract inputs from request
   */
  _extractInputs(req) {
    return {
      ...req.body,
      ...req.query,
      ...req.params,
    };
  }

  /**
   * Standalone check method
   */
  check(input) {
    return this.detect(input);
  }

  /**
   * Batch check multiple inputs
   */
  checkBatch(inputs) {
    return inputs.map((input) => this.detect(input));
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      cacheSize: this.cache.size,
      maxCacheSize: this.config.performance.cacheSize,
      bloomFilterSize: this.config.bloomFilter.size,
      mode: this.config.mode,
      config: this.config,
    };
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
  }
}

module.exports = SQLInjectionDetector;
