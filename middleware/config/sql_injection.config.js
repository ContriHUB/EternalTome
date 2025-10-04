/**
 * SQL Injection Detection Configuration
 *
 * This configuration file allows you to customize the behavior of the SQL injection detector
 */

module.exports = {
  // Detection mode: 'bloom+heuristic' or 'bloom+heuristic+ast'
  // 'bloom+heuristic' - Fast, good for high-traffic endpoints
  // 'bloom+heuristic+ast' - More accurate, use for critical endpoints
  mode: "bloom+heuristic",

  // Bloom Filter Configuration
  // Used for fast whitelist checking of known safe patterns
  bloomFilter: {
    enabled: true,

    // Size of the bloom filter bit array (larger = fewer false positives)
    size: 30000,

    // Number of hash functions to use
    hashFunctions: 4,

    // Custom whitelist patterns (safe words/phrases)
    // These will be added to the default whitelist
    whitelist: [
      // Add your application-specific safe patterns here
      // Examples:
      // 'username',
      // 'email',
      // 'search query',
      "username",
      "email",
      "search",
      "q",
      "page",
      "limit",
      "offset",
      "order",
      "by",
      "name",
      "id",
      "post_id",
      "meta_key",
      "meta_value",
      "category",
      "filter",
    ],
  },

  // Heuristic Pattern Matching Configuration
  // Detects SQL injection through weighted pattern matching
  heuristic: {
    enabled: true,

    // Threshold score for blocking (higher = less sensitive)
    // SECURITY-FIRST APPROACH: Lower threshold = better detection, some false positives acceptable
    // Recommended: 3 for maximum security (prioritizes catching attacks)
    //              5 for balanced approach
    //              7-8 for production with low false positive tolerance
    threshold: 3,

    // Weight for each detection pattern
    // Higher weights = more important patterns
    // These weights are aggressive to ensure 100% malicious query detection
    weights: {
      // SQL keywords (SELECT, UNION, DROP, etc.)
      sqlKeywords: 2,

      // SQL comment patterns (--, /*, */)
      commentPatterns: 2,

      // Unbalanced quotes (' or ")
      quoteAnomalies: 4,

      // UNION-based attacks
      unionAttacks: 4,

      // Multiple statements (stacked queries)
      stackedQueries: 6,

      // URL encoded or hex encoded characters
      encodedChars: 2,

      // Hex patterns (0x, char(), ascii())
      hexPatterns: 3,
    },
  },

  // AST Parser Configuration
  // Parses input as SQL and analyzes syntax tree
  // Requires: npm install node-sql-parser
  astParser: {
    // Enable AST parsing (only works if mode is 'bloom+heuristic+ast')
    enabled: false,

    // SQL dialect to parse
    // Options: 'mysql', 'postgres', 'sqlite', 'mariadb'
    sqlDialect: "mysql",

    // Maximum allowed nesting depth in queries
    // Helps prevent overly complex malicious queries
    maxNestingDepth: 10,

    // SQL operations that should always be blocked
    // These are high-risk operations
    blockedOperations: [
      "DROP",
      "DELETE",
      "TRUNCATE",
      "ALTER",
      "EXEC",
      "EXECUTE",
      "CREATE",
      "GRANT",
      "REVOKE",
    ],

    // Allow multiple SQL statements in one input
    // Usually should be false for security
    allowMultipleStatements: false,
  },

  // Performance Configuration
  performance: {
    // Enable result caching (improves performance for repeated inputs)
    enableCaching: true,

    // Maximum number of cached results (LRU policy)
    cacheSize: 20000,

    // Maximum execution time per check (milliseconds)
    timeout: 100,
  },

  // Action to take when SQL injection is detected
  onDetection: {
    // Action: 'block', 'sanitize', or 'log'
    // 'block' - Reject the request with 403 error
    // 'sanitize' - Clean the input and continue
    // 'log' - Only log the detection, allow request
    action: "block",

    // Sanitization strategy (used when action is 'sanitize')
    // 'escape' - Escape SQL special characters
    // 'remove' - Remove dangerous patterns
    // 'encode' - Base64 encode the input
    sanitizationStrategy: "escape",

    // Return detailed error to client (set false for production)
    returnError: true,

    // Custom error message shown to users
    customErrorMessage:
      "Invalid input detected. Please check your input and try again.",
  },

  // Route-specific configuration (optional)
  // Allows different settings for different endpoints
  routes: {
    // Example: Strict security for authentication endpoints
    "/api/auth/login": {
      mode: "bloom+heuristic+ast",
      heuristic: { threshold: 5 },
      astParser: { enabled: true },
    },

    "/api/auth/register": {
      mode: "bloom+heuristic+ast",
      heuristic: { threshold: 5 },
      astParser: { enabled: true },
    },

    // Example: Balanced security for search
    "/api/search": {
      mode: "bloom+heuristic",
      heuristic: { threshold: 8 },
    },

    // Example: Relaxed for public endpoints
    "/api/public": {
      mode: "bloom+heuristic",
      heuristic: { threshold: 10 },
    },
  },

  // Logging Configuration
  logging: {
    // Log all checks (verbose, use only for debugging)
    logAllChecks: false,

    // Log only when SQL injection is detected
    logBlockedOnly: true,

    // Log slow queries (AST parsing taking too long)
    logSlowQueries: true,

    // Time threshold for slow query logging (milliseconds)
    slowQueryThreshold: 50,

    // Alert if multiple attacks detected in short time
    alertThreshold: 10, // Number of blocks
    alertWindow: 60000, // Time window in milliseconds (1 minute)
  },

  // Development/Testing Configuration
  development: {
    // Disable all checks in development (NOT RECOMMENDED)
    disableInDev: false,

    // Environment variable to check
    envVariable: "NODE_ENV",

    // Values that indicate development environment
    devEnvironments: ["development", "dev", "test"],
  },
};
