// ssrfConfig.js - Configuration for SSRF Protection
const path = require("path");

const SSRFConfigOptions = {
  // Enable/Disable entire SSRF protection
  enabled: true,

  // Asset files directory
  assetsPath: path.join(__dirname, "../assets"),

  // Feature toggles
  checks: {
    protocolValidation: true, // Check if URL protocol is allowed
    domainWhitelist: true, // Check domain whitelist (bypasses other checks)
    domainBlacklist: true, // Check domain blacklist
    ipWhitelist: true, // Check IP whitelist
    ipBlacklist: true, // Check IP blacklist
    privateIPBlocking: true, // Block private/internal IPs
    dnsResolution: true, // Perform DNS resolution
  },

  // DNS settings
  dns: {
    enabled: true,
    timeout: 5000, // DNS lookup timeout in ms
    family: 0, // 0=both IPv4/IPv6, 4=IPv4 only, 6=IPv6 only
    retries: 2, // Number of DNS retry attempts
  },

  // Cache settings
  cache: {
    enabled: true,
    ttl: 60000, // Cache TTL in ms (1 minute)
    maxSize: 1000, // Maximum cached config entries
  },

  // Logging
  logging: {
    logAllowed: true, // Log allowed URLs
    logBlocked: true, // Log blocked URLs
    logDNSFailures: true, // Log DNS resolution failures
    verboseMode: false, // Detailed logging for debugging
  },

  // Behavior settings
  behavior: {
    whitelistBypassesAll: true, // Whitelisted domains skip all other checks
    failOpen: false, // Allow requests if SSRF check fails (NOT RECOMMENDED)
    strictMode: true, // Strict validation (recommended)
  },

  // Response settings
  response: {
    includeReason: true, // Include failure reason in response
    includeErrorCode: true, // Include error code in response
    statusCode: 403, // HTTP status code for blocked requests
  },

  // Config file names
  files: {
    whitelistDomain: "whitelistDomain.txt",
    blacklistDomain: "blacklistDomain.txt",
    whitelistIP: "whitelistIP.txt",
    blacklistIP: "blacklistIP.txt",
    allowedProtocols: "allowedProtocols.txt",
  },
};

module.exports = SSRFConfigOptions;
