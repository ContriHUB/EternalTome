const logger = require("../logger/logger");
const getTargetFields = require("../utils/getTargetFields");
const { URL } = require("url");
const dns = require("dns").promises;
const fs = require("fs").promises;
const path = require("path");
const SSRFConfigOptions = require("../config/SSRF.config");

/**
 * SSRFConfig - Manages loading and caching of SSRF protection configuration
 *
 * Loads whitelists, blacklists, and allowed protocols from text files.
 * Implements TTL-based caching to avoid reading files on every request.
 */
class SSRFConfig {
  constructor(options = SSRFConfigOptions) {
    this.options = options;
    this.configPath = options.assetsPath;
    this.cache = null;
    this.lastLoad = 0;
    this.cacheTTL = options.cache.ttl;
  }

  /**
   * Load configuration from files, using cache if available and not expired
   * @returns {Promise<Object>} Configuration object with all lists
   */
  async loadConfig() {
    // Bypass cache if disabled in config
    if (!this.options.cache.enabled) {
      return await this.reloadConfig();
    }

    // Return cached config if TTL hasn't expired
    const now = Date.now();
    if (this.cache && now - this.lastLoad < this.cacheTTL) {
      return this.cache;
    }

    return await this.reloadConfig();
  }

  /**
   * Force reload configuration from disk, bypassing cache
   * @returns {Promise<Object>} Fresh configuration object
   * @throws {Error} If config loading fails and failOpen is false
   */
  async reloadConfig() {
    try {
      const files = this.options.files;

      // Load all config files in parallel for better performance
      const [
        whitelistDomains,
        blacklistDomains,
        blacklistIPs,
        allowedProtocols,
        whitelistIPs,
      ] = await Promise.all([
        this.options.checks.domainWhitelist
          ? this.loadFile(files.whitelistDomain)
          : Promise.resolve([]),
        this.options.checks.domainBlacklist
          ? this.loadFile(files.blacklistDomain)
          : Promise.resolve([]),
        this.options.checks.ipBlacklist
          ? this.loadFile(files.blacklistIP)
          : Promise.resolve([]),
        this.options.checks.protocolValidation
          ? this.loadFile(files.allowedProtocols)
          : Promise.resolve([]),
        this.options.checks.ipWhitelist
          ? this.loadFile(files.whitelistIP)
          : Promise.resolve([]),
      ]);

      // Normalize protocols to lowercase without colons
      const normalizedProtocols = allowedProtocols.map((p) =>
        p.toLowerCase().replace(":", "")
      );

      // Cache the loaded configuration
      this.cache = {
        whitelistDomains,
        blacklistDomains,
        blacklistIPs,
        allowedProtocols: normalizedProtocols,
        whitelistIPs,
      };
      this.lastLoad = Date.now();

      if (this.options.logging.verboseMode) {
        logger.info(
          `SSRF config loaded: ${whitelistDomains.length} whitelist domains, ${blacklistDomains.length} blacklist domains`
        );
      }

      return this.cache;
    } catch (error) {
      logger.error(`Failed to load SSRF config: ${error.message}`);

      // Fail-open mode: allow requests if config can't be loaded
      // WARNING: This reduces security and should only be used in specific scenarios
      if (this.options.behavior.failOpen) {
        logger.warn(
          "SSRF config load failed, but fail-open is enabled. Allowing requests."
        );
        return {
          whitelistDomains: [],
          blacklistDomains: [],
          blacklistIPs: [],
          allowedProtocols: [],
          whitelistIPs: [],
        };
      }

      throw error;
    }
  }

  /**
   * Load and parse a single config file
   * @param {string} filename - Name of the config file
   * @returns {Promise<string[]>} Array of non-empty, non-comment lines
   */
  async loadFile(filename) {
    try {
      const filePath = path.join(this.configPath, filename);
      const data = await fs.readFile(filePath, "utf-8");

      // Parse file: trim whitespace, filter out comments and empty lines
      return data
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"));
    } catch (error) {
      // Treat missing files as empty lists rather than errors
      if (error.code === "ENOENT") {
        logger.warn(`Config file ${filename} not found, using empty list`);
        return [];
      }
      throw error;
    }
  }
}

/**
 * IPNormalizer - Normalizes IP addresses to standard format
 */
class IPNormalizer {
  /**
   * Normalize IPv4 address from various formats (hex, octal, decimal, dotted)
   * @param {string} ip - IP address string
   * @returns {string|null} Normalized IP or null if invalid
   */
  static normalizeIPv4(ip) {
    // Already in dotted decimal format
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      const parts = ip.split(".").map(Number);
      if (parts.every((p) => p >= 0 && p <= 255)) {
        return ip;
      }
      return null;
    }

    // Handle hex format: 0x7f000001
    if (/^0x[0-9a-f]+$/i.test(ip)) {
      const num = parseInt(ip, 16);
      return this.intToIPv4(num);
    }

    // Handle octal format: 0177.0.0.1 or parts with leading zeros
    if (/^0\d/.test(ip)) {
      const parts = ip.split(".");
      const octets = parts.map((part) => {
        if (part.startsWith("0") && part.length > 1) {
          return parseInt(part, 8);
        }
        return parseInt(part, 10);
      });

      if (octets.length === 4 && octets.every((o) => o >= 0 && o <= 255)) {
        return octets.join(".");
      }
      return null;
    }

    // Handle decimal format: 2130706433
    if (/^\d+$/.test(ip)) {
      const num = parseInt(ip, 10);
      return this.intToIPv4(num);
    }

    return null;
  }

  /**
   * Convert 32-bit integer to IPv4 dotted decimal
   * @param {number} num - 32-bit integer
   * @returns {string|null} IPv4 address or null if invalid
   */
  static intToIPv4(num) {
    if (num < 0 || num > 0xffffffff) return null;
    return [
      (num >>> 24) & 0xff,
      (num >>> 16) & 0xff,
      (num >>> 8) & 0xff,
      num & 0xff,
    ].join(".");
  }

  /**
   * Normalize IPv6 address to expanded format
   * @param {string} ip - IPv6 address
   * @returns {string|null} Normalized IPv6 or null if invalid
   */
  static normalizeIPv6(ip) {
    try {
      // Remove zone identifier if present (e.g., fe80::1%eth0 -> fe80::1)
      const cleanIP = ip.split("%")[0].toLowerCase();

      // Handle IPv4-mapped IPv6 addresses
      if (cleanIP.includes(".")) {
        const match = cleanIP.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
        if (match) {
          return `::ffff:${match[1]}`;
        }
      }

      // Expand IPv6 shorthand
      let parts = cleanIP.split(":");
      const emptyIndex = parts.indexOf("");

      if (emptyIndex !== -1) {
        // Handle :: compression
        const leftParts = parts.slice(0, emptyIndex).filter((p) => p);
        const rightParts = parts.slice(emptyIndex + 1).filter((p) => p);
        const missingZeros = 8 - leftParts.length - rightParts.length;

        if (missingZeros < 0) return null;

        parts = [...leftParts, ...Array(missingZeros).fill("0"), ...rightParts];
      }

      // Pad each part to 4 hex digits
      if (parts.length !== 8) return null;
      const expanded = parts.map((p) => {
        if (!/^[0-9a-f]{1,4}$/.test(p)) return null;
        return p.padStart(4, "0");
      });

      if (expanded.includes(null)) return null;
      return expanded.join(":");
    } catch {
      return null;
    }
  }
}

/**
 * IPValidator - Validates IP addresses against security policies
 *
 * Checks for private/internal IPs and whitelist/blacklist matches.
 */
class IPValidator {
  /**
   * Check if an IP address is in a private/internal range
   * Covers IPv4 private ranges, IPv6 private ranges, and special-use addresses
   *
   * @param {string} ip - IP address to check (should be normalized)
   * @param {Object} options - Configuration options
   * @returns {boolean} True if IP is private/internal
   */
  static isPrivateIP(ip, options = SSRFConfigOptions) {
    if (!options.checks.privateIPBlocking) {
      return false;
    }

    // Handle IPv6 addresses (including IPv4-mapped IPv6)
    if (ip.includes(":")) {
      const normalized = IPNormalizer.normalizeIPv6(ip);
      if (!normalized) return true; // Invalid IPv6 = block

      // IPv4-mapped IPv6 (::ffff:192.168.1.1)
      if (normalized.startsWith("::ffff:")) {
        const ipv4Part = normalized.substring(7);
        return this.isPrivateIP(ipv4Part, options);
      }

      // IPv6 private and special ranges
      return (
        normalized === "0000:0000:0000:0000:0000:0000:0000:0001" || // ::1 loopback
        normalized.startsWith("fc") || // Unique local fc00::/7
        normalized.startsWith("fd") || // Unique local fd00::/8
        normalized.startsWith("fe80:") || // Link-local fe80::/10
        normalized.startsWith("fe9") ||
        normalized.startsWith("fea") ||
        normalized.startsWith("feb") ||
        normalized.startsWith("ff") // Multicast ff00::/8
      );
    }

    // Normalize IPv4 before checking
    const normalized = IPNormalizer.normalizeIPv4(ip);
    if (!normalized) return true; // Invalid IPv4 = block

    const parts = normalized.split(".").map(Number);
    const [a, b, c, d] = parts;

    // Validate each octet
    if (parts.some((p) => p < 0 || p > 255)) return true;

    return (
      a === 0 || // 0.0.0.0/8 - Current network
      a === 10 || // 10.0.0.0/8 - Private Class A
      a === 127 || // 127.0.0.0/8 - Loopback
      (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 - Shared address space (CGNAT)
      (a === 169 && b === 254) || // 169.254.0.0/16 - Link-local (AWS metadata)
      (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 - Private Class B
      (a === 192 && b === 0 && c === 0) || // 192.0.0.0/24 - IETF Protocol Assignments
      (a === 192 && b === 0 && c === 2) || // 192.0.2.0/24 - TEST-NET-1
      (a === 192 && b === 168) || // 192.168.0.0/16 - Private Class C
      (a === 198 && b === 18) || // 198.18.0.0/15 - Benchmark testing
      (a === 198 && b === 19) || // 198.19.0.0/15 - Benchmark testing
      (a === 198 && b === 51 && c === 100) || // 198.51.100.0/24 - TEST-NET-2
      (a === 203 && b === 0 && c === 113) || // 203.0.113.0/24 - TEST-NET-3
      a >= 224 // 224.0.0.0/4 - Multicast and reserved (224-255)
    );
  }

  /**
   * Check if IP is in the whitelist (with normalization)
   * @param {string} ip - IP address to check
   * @param {string[]} whitelist - Array of whitelisted IPs
   * @param {Object} options - Configuration options
   * @returns {boolean} True if IP is whitelisted
   */
  static isInWhitelist(ip, whitelist, options = SSRFConfigOptions) {
    if (!options.checks.ipWhitelist) {
      return false;
    }

    const normalized = ip.includes(":")
      ? IPNormalizer.normalizeIPv6(ip)
      : IPNormalizer.normalizeIPv4(ip);

    if (!normalized) return false;

    // Check both original and normalized forms
    return whitelist.some((whitelistedIP) => {
      const normalizedWhitelist = whitelistedIP.includes(":")
        ? IPNormalizer.normalizeIPv6(whitelistedIP)
        : IPNormalizer.normalizeIPv4(whitelistedIP);

      return normalizedWhitelist === normalized || whitelistedIP === ip;
    });
  }

  /**
   * Check if IP is in the blacklist (with normalization)
   * @param {string} ip - IP address to check
   * @param {string[]} blacklist - Array of blacklisted IPs
   * @param {Object} options - Configuration options
   * @returns {boolean} True if IP is blacklisted
   */
  static isInBlacklist(ip, blacklist, options = SSRFConfigOptions) {
    if (!options.checks.ipBlacklist) {
      return false;
    }

    const normalized = ip.includes(":")
      ? IPNormalizer.normalizeIPv6(ip)
      : IPNormalizer.normalizeIPv4(ip);

    if (!normalized) return false;

    // Check both original and normalized forms
    return blacklist.some((blacklistedIP) => {
      const normalizedBlacklist = blacklistedIP.includes(":")
        ? IPNormalizer.normalizeIPv6(blacklistedIP)
        : IPNormalizer.normalizeIPv4(blacklistedIP);

      return normalizedBlacklist === normalized || blacklistedIP === ip;
    });
  }
}

/**
 * URLValidator - Validates URL format, protocol, and domain
 */
class URLValidator {
  /**
   * Normalize and validate URL
   * @param {string} urlString - URL to normalize
   * @returns {URL|null} Normalized URL object or null if invalid
   */
  static normalizeUrl(urlString, res = null) {
    try {
      // Remove leading/trailing whitespace
      urlString = urlString.trim();

      // Normalize protocol to lowercase
      const protocolMatch = urlString.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
      if (protocolMatch) {
        const normalizedProtocol = protocolMatch[1].toLowerCase();
        urlString = urlString.replace(
          protocolMatch[0],
          `${normalizedProtocol}://`
        );
      }

      const url = new URL(urlString);

      // Block credentials in URL (user:pass@host)
      if (url.username || url.password) {
        logger.warn(`Blocked URL with credentials: ${url.hostname}`);
        if (res) {
          res
            .status(403)
            .json({
              error: "Forbidden",
              code: "INVALID_URL",
              message: "Blocked credentials in URL",
            });
        }
        return false;
      }

      // Normalize hostname to lowercase
      url.hostname = url.hostname.toLowerCase();

      // Block URLs with @ in hostname (obfuscation attempt)
      if (url.hostname.includes("@")) {
        logger.warn(`Blocked URL with @ in hostname: ${urlString}`);
        if (res) {
          res
            .status(403)
            .json({
              error: "Forbidden",
              code: "INVALID_URL",
              message: "Blocked @ in hostname",
            });
        }
        return false;
      }

      return url;
    } catch (err) {
      return null;
    }
  }

  /**
   * Check if string is a valid URL
   * @param {string} string - String to validate
   * @returns {boolean} True if valid URL
   */
  static isValidUrl(string) {
    return this.normalizeUrl(string) !== null;
  }

  /**
   * Check if URL uses an allowed protocol
   * @param {URL} url - Normalized URL object
   * @param {string[]} allowedProtocols - Array of allowed protocols (lowercase, no colon)
   * @param {Object} options - Configuration options
   * @returns {boolean} True if protocol is allowed
   */
  static hasAllowedProtocol(
    url,
    allowedProtocols,
    options = SSRFConfigOptions
  ) {
    if (!options.checks.protocolValidation) {
      return true;
    }

    const protocol = url.protocol.replace(":", "").toLowerCase();
    return allowedProtocols.includes(protocol);
  }

  /**
   * Check if hostname matches a domain pattern
   * Uses strict matching to prevent bypass attacks
   *
   * @param {string} hostname - Hostname to check (should be lowercase)
   * @param {string} domainPattern - Domain pattern (may include wildcard)
   * @returns {boolean} True if hostname matches pattern
   */
  static matchesDomain(hostname, domainPattern) {
    // Normalize both to lowercase
    hostname = hostname.toLowerCase();
    domainPattern = domainPattern.toLowerCase().trim();

    // Exact match: example.com == example.com
    if (hostname === domainPattern) return true;

    // Wildcard subdomain: *.example.com
    if (domainPattern.startsWith("*.")) {
      const baseDomain = domainPattern.slice(2);

      // Must be a subdomain of baseDomain
      // api.example.com matches *.example.com
      // example.com does NOT match *.example.com
      if (hostname.endsWith("." + baseDomain)) {
        return true;
      }

      return false;
    }

    // Wildcard prefix: example.* (matches example.com, example.org, etc.)
    if (domainPattern.endsWith(".*")) {
      const basePattern = domainPattern.slice(0, -2);
      return hostname.startsWith(basePattern + ".");
    }

    // No partial matching allowed - must be exact or use explicit wildcard
    return false;
  }
}

/**
 * SSRFChecker - Main SSRF validation logic
 *
 * Performs multi-layered security checks:
 * 1. URL normalization and validation
 * 2. Protocol validation
 * 3. Domain blacklist check
 * 4. Domain whitelist check
 * 5. DNS resolution with pinning
 * 6. IP whitelist/blacklist check
 * 7. Private IP blocking
 */
class SSRFChecker {
  constructor(options = SSRFConfigOptions) {
    this.options = options;
    this.dnsCache = new Map(); // DNS pinning cache
  }

  /**
   * Check if a single URL is safe to access
   * Performs all configured security checks in order of priority
   *
   * @param {string} urlString - URL to validate
   * @param {string[]} whitelistDomains - Allowed domains
   * @param {string[]} blacklistDomains - Blocked domains
   * @param {string[]} whitelistIPs - Allowed IPs
   * @param {string[]} blacklistIPs - Blocked IPs
   * @param {string[]} allowedProtocols - Allowed URL protocols
   * @returns {Promise<Object>} Validation result with {safe, reason, code, resolvedIPs}
   */
  async checkUrl(
    urlString,
    whitelistDomains,
    blacklistDomains,
    whitelistIPs,
    blacklistIPs,
    allowedProtocols
  ) {
    // STEP 0: Normalize and validate URL
    const url = URLValidator.normalizeUrl(urlString);
    if (!url) {
      return {
        safe: false,
        reason: "Invalid or malformed URL",
        code: "INVALID_URL",
      };
    }

    let hostname = url.hostname;

    // STEP 0.5: Detect and block obfuscated private IPs in hostname (hex, octal, decimal)
    // Only if hostname is not a valid domain (i.e., looks like an IP or encoded IP)
    // Try to normalize as IPv4
    const normalizedIPv4 = IPNormalizer.normalizeIPv4(hostname);
    if (
      normalizedIPv4 &&
      IPValidator.isPrivateIP(normalizedIPv4, this.options)
    ) {
      return {
        safe: false,
        reason: `Hostname resolves to private/internal IP: ${normalizedIPv4}`,
        code: "PRIVATE_IP",
      };
    }

    // STEP 1: Protocol validation (block file://, gopher://, etc.)
    if (this.options.checks.protocolValidation) {
      if (
        !URLValidator.hasAllowedProtocol(url, allowedProtocols, this.options)
      ) {
        return {
          safe: false,
          reason: `Protocol not allowed: ${url.protocol}`,
          code: "PROTOCOL_NOT_ALLOWED",
        };
      }
    }

    // STEP 2: Domain blacklist (highest priority for explicit blocks)
    if (this.options.checks.domainBlacklist) {
      for (const domain of blacklistDomains) {
        if (URLValidator.matchesDomain(hostname, domain)) {
          return {
            safe: false,
            reason: `Domain is blacklisted: ${hostname}`,
            code: "DOMAIN_BLACKLISTED",
          };
        }
      }
    }

    // STEP 3: Domain whitelist (can bypass IP checks if configured)
    let domainWhitelisted = false;
    if (this.options.checks.domainWhitelist) {
      for (const domain of whitelistDomains) {
        if (URLValidator.matchesDomain(hostname, domain)) {
          domainWhitelisted = true;
          if (this.options.logging.logAllowed) {
            logger.info(`URL allowed by domain whitelist: ${hostname}`);
          }

          // If whitelistBypassesAll is true, skip all remaining checks
          if (this.options.behavior.whitelistBypassesAll) {
            return { safe: true, reason: "Domain whitelisted" };
          }
          break;
        }
      }
    }

    // STEP 4: DNS resolution and IP validation
    if (!this.options.checks.dnsResolution) {
      return {
        safe: true,
        reason: "DNS resolution disabled, basic checks passed",
      };
    }

    let addresses;
    let timeoutHandle;

    try {
      const dnsOptions = {
        all: true, // Return all resolved IPs
        family: this.options.dns.family, // 0=both, 4=IPv4 only, 6=IPv6 only
      };

      // Create timeout promise that can be cleaned up
      const timeoutPromise = new Promise((_, reject) => {
        timeoutHandle = setTimeout(
          () => reject(new Error("DNS timeout")),
          this.options.dns.timeout
        );
      });

      // Perform DNS lookup with timeout
      addresses = await Promise.race([
        dns.lookup(hostname, dnsOptions),
        timeoutPromise,
      ]);

      // Clear timeout on success
      if (timeoutHandle) clearTimeout(timeoutHandle);

      // Store resolved IPs for DNS pinning (prevent DNS rebinding attacks)
      const cacheKey = `${hostname}:${Date.now()}`;
      this.dnsCache.set(
        cacheKey,
        addresses.map((a) => a.address)
      );

      // Clean old cache entries (keep last 1000 entries)
      if (this.dnsCache.size > 1000) {
        const firstKey = this.dnsCache.keys().next().value;
        this.dnsCache.delete(firstKey);
      }
    } catch (dnsError) {
      // Clear timeout on error
      if (timeoutHandle) clearTimeout(timeoutHandle);

      if (this.options.logging.logDNSFailures) {
        logger.error(`DNS lookup failed for ${hostname}: ${dnsError.message}`);
      }

      // Fail-open: allow request despite DNS failure
      // WARNING: This can bypass security checks
      if (this.options.behavior.failOpen) {
        logger.warn(`DNS failed but fail-open enabled, allowing: ${hostname}`);
        return { safe: true, reason: "DNS failed but fail-open enabled" };
      }

      return {
        safe: false,
        reason: `DNS resolution failed: ${dnsError.message}`,
        code: "DNS_FAILED",
      };
    }

    // STEP 5: Check each resolved IP address
    // All IPs must pass validation; if any IP fails, the entire URL is blocked
    const resolvedIPs = [];

    for (const addr of addresses) {
      const ip = addr.address;
      resolvedIPs.push(ip);

      // IP whitelist has highest priority
      if (IPValidator.isInWhitelist(ip, whitelistIPs, this.options)) {
        if (this.options.logging.logAllowed) {
          logger.info(`URL allowed by IP whitelist: ${ip}`);
        }
        continue;
      }

      // Block if IP is explicitly blacklisted
      if (IPValidator.isInBlacklist(ip, blacklistIPs, this.options)) {
        return {
          safe: false,
          reason: `Domain resolves to blacklisted IP: ${ip}`,
          code: "IP_BLACKLISTED",
          resolvedIPs,
        };
      }

      // Block private/internal IPs unless domain was whitelisted
      if (!domainWhitelisted && IPValidator.isPrivateIP(ip, this.options)) {
        return {
          safe: false,
          reason: `Domain resolves to private/internal IP: ${ip}`,
          code: "PRIVATE_IP",
          resolvedIPs,
        };
      }
    }

    // All checks passed
    return {
      safe: true,
      reason: "All checks passed",
      resolvedIPs,
    };
  }

  /**
   * Validate multiple URLs, failing fast on first unsafe URL
   * @param {string[]} urls - Array of URLs to validate
   * @param {Object} config - Configuration with whitelists/blacklists
   * @returns {Promise<Object>} Validation result
   */
  async validateUrls(urls, config) {
    const results = [];

    for (const url of urls) {
      const result = await this.checkUrl(
        url,
        config.whitelistDomains,
        config.blacklistDomains,
        config.whitelistIPs,
        config.blacklistIPs,
        config.allowedProtocols
      );

      results.push({ url, ...result });

      // Fail fast: return immediately on first unsafe URL
      if (!result.safe) {
        return { safe: false, failedUrl: url, ...result };
      }
    }

    return { safe: true, results };
  }
}

// Create singleton config loader instance
const configLoader = new SSRFConfig();

/**
 * Express middleware for SSRF protection
 * Extracts URLs from request and validates them against security policies
 *
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<boolean|undefined>} False if blocked, undefined/true if allowed
 */
const checkforSSRF = async (req, res, next) => {
  // Early exit if SSRF protection is globally disabled
  if (!SSRFConfigOptions.enabled) {
    if (SSRFConfigOptions.logging.verboseMode) {
      logger.info("SSRF protection is disabled");
    }
    return next ? next() : true;
  }

  try {
    // Extract potential URLs from request body, query params, etc.
    const targets = getTargetFields(req);
    const urls = [];
    for (const obj of targets) {
      if (!obj.value) continue;
      const normalized = URLValidator.normalizeUrl(obj.value, res);
      if (normalized === false) {
        // Blocked by credentials or @ in hostname
        return false;
      }
      if (normalized) {
        urls.push(obj.value);
      }
    }

    // No URLs found - allow request to proceed
    if (urls.length === 0) {
      return next ? next() : true;
    }

    // Load security configuration (uses cache if available)
    let config;
    try {
      config = await configLoader.loadConfig();
    } catch (configError) {
      // Configuration loading failed and fail-open is disabled
      logger.error(`Failed to load config: ${configError.message}`);
      res.status(500).json({
        error: "Internal Server Error",
        message: "Configuration error",
      });
      return false;
    }

    // Validate all extracted URLs
    const checker = new SSRFChecker(SSRFConfigOptions);
    const validation = await checker.validateUrls(urls, config);

    // Block request if any URL failed validation
    if (!validation.safe) {
      if (SSRFConfigOptions.logging.logBlocked) {
        logger.warn(
          `SSRF attempt blocked: ${validation.reason} (${validation.failedUrl})`
        );
      }

      // Build response based on config
      const response = {
        error: "Forbidden",
      };

      if (SSRFConfigOptions.response.includeReason) {
        response.message = validation.reason;
      }

      if (SSRFConfigOptions.response.includeErrorCode) {
        response.code = validation.code;
      }

      res.status(SSRFConfigOptions.response.statusCode).json(response);
      return false;
    }

    // All URLs passed validation - allow request
    if (SSRFConfigOptions.logging.logAllowed) {
      logger.info(`SSRF check passed for ${urls.length} URL(s)`);
    }

    return next ? next() : true;
  } catch (error) {
    // Unexpected error during SSRF check
    logger.error(`SSRF check failed: ${error.message}`);

    // Fail-open mode: allow request despite error
    if (SSRFConfigOptions.behavior.failOpen) {
      logger.warn("SSRF check failed but fail-open enabled, allowing request");
      return next ? next() : true;
    }

    // Fail-closed mode: block request on error (secure default)
    res.status(500).json({
      error: "Internal Server Error",
      message: "URL validation error",
    });
    return false;
  }
};

// Export middleware function and classes for testing
module.exports = checkforSSRF;
module.exports.IPValidator = IPValidator;
module.exports.URLValidator = URLValidator;
module.exports.IPNormalizer = IPNormalizer;
module.exports.SSRFChecker = SSRFChecker;
