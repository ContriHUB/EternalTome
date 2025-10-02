// ssrf.test.js - Comprehensive Jest test suite for SSRF middleware

jest.mock("../logger/logger", () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

jest.mock("../utils/getTargetFields");

jest.mock("dns", () => ({
  promises: {
    lookup: jest.fn(),
  },
}));

jest.mock("fs", () => ({
  promises: {
    readFile: jest.fn(),
  },
}));

const checkforSSRF = require("../checks/serversideforgery");
const { URLValidator } = require("../checks/serversideforgery");
const logger = require("../logger/logger");
const getTargetFields = require("../utils/getTargetFields");
const dns = require("dns");
const fs = require("fs");

describe("SSRF Middleware Tests", () => {
  let req, res, next;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Mock request and response
    req = {
      body: {},
      query: {},
      params: {},
      headers: {},
    };

    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
    };

    next = jest.fn();

    // Mock configuration files
    fs.promises.readFile.mockImplementation((path) => {
      if (path.includes("whitelistDomain")) {
        return Promise.resolve("example.com\n*.trusted.com\n# comment line");
      }
      if (path.includes("blacklistDomain")) {
        return Promise.resolve("evil.com\nmalicious.net\n*.spam.com");
      }
      if (path.includes("whitelistIP")) {
        return Promise.resolve("8.8.8.8\n1.1.1.1");
      }
      if (path.includes("blacklistIP")) {
        return Promise.resolve("6.6.6.6\n66.66.66.66");
      }
      if (path.includes("allowedProtocols")) {
        return Promise.resolve("http\nhttps\nftp");
      }
      return Promise.resolve("");
    });

    // Default DNS mock - public IP
    dns.promises.lookup.mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
    ]);
  });

  describe("Basic Functionality", () => {
    test("should allow requests with no URLs", async () => {
      getTargetFields.mockReturnValue([]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should extract and validate URLs from request", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://public-api-1.com" },
        { value: "not-a-url" },
        { value: "https://public-api-2.com" },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(dns.promises.lookup).toHaveBeenCalledTimes(2);
    });

    test("should handle middleware with next() callback", async () => {
      getTargetFields.mockReturnValue([{ value: "https://example.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("Protocol Validation", () => {
    test("should allow URLs with permitted protocols - http", async () => {
      getTargetFields.mockReturnValue([{ value: "http://example.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test("should allow URLs with permitted protocols - https", async () => {
      getTargetFields.mockReturnValue([{ value: "https://secure.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should allow URLs with permitted protocols - ftp", async () => {
      getTargetFields.mockReturnValue([{ value: "ftp://files.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should block URLs with forbidden protocols - file", async () => {
      getTargetFields.mockReturnValue([{ value: "file:///etc/passwd" }]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PROTOCOL_NOT_ALLOWED" })
      );
    });

    test("should block URLs with forbidden protocols - gopher", async () => {
      getTargetFields.mockReturnValue([{ value: "gopher://archive.com" }]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PROTOCOL_NOT_ALLOWED" })
      );
    });

    test("should block URLs with forbidden protocols - data", async () => {
      getTargetFields.mockReturnValue([
        { value: "data:text/html,<script>alert(1)</script>" },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });
  });

  describe("Domain Whitelist", () => {
    test("should allow exact whitelisted domain", async () => {
      getTargetFields.mockReturnValue([{ value: "https://example.com/api" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining("whitelist")
      );
    });

    test("should allow wildcard subdomain matches", async () => {
      getTargetFields.mockReturnValue([{ value: "https://api.trusted.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should allow deeper subdomain matches", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://v1.api.trusted.com" },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should not match partial domain strings", async () => {
      getTargetFields.mockReturnValue([{ value: "https://notexample.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "1.2.3.4", family: 4 },
      ]);

      await checkforSSRF(req, res, next);

      // Should still pass (public IP) but not via whitelist
      expect(next).toHaveBeenCalled();
    });
  });

  describe("Domain Blacklist", () => {
    test("should block exact blacklisted domain", async () => {
      getTargetFields.mockReturnValue([{ value: "https://evil.com" }]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "DOMAIN_BLACKLISTED" })
      );
    });

    test("should block blacklisted domain with path", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://malicious.net/attack" },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "DOMAIN_BLACKLISTED" })
      );
    });

    test("should block wildcard blacklisted domains", async () => {
      getTargetFields.mockReturnValue([{ value: "https://phishing.spam.com" }]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });
  });
  describe("IP Normalization Security", () => {
    test("blocks hex-encoded localhost", async () => {
      getTargetFields.mockReturnValue([{ value: "http://0x7f000001" }]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });

    test("blocks octal-encoded private IP", async () => {
      getTargetFields.mockReturnValue([{ value: "http://0177.0.0.1" }]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
    });

    test("blocks decimal IP representation", async () => {
      getTargetFields.mockReturnValue([{ value: "http://2130706433" }]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
    });
  });

  describe("URL Normalization Security", () => {
    test("blocks URLs with credentials", async () => {
      getTargetFields.mockReturnValue([{ value: "http://user:pass@evil.com" }]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "INVALID_URL" })
      );
    });

    test("blocks @ symbol in hostname", async () => {
      getTargetFields.mockReturnValue([{ value: "http://trusted@evil.com" }]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
    });

    test("normalizes protocol case", async () => {
      getTargetFields.mockReturnValue([{ value: "HTTP://Example.COM" }]);
      await checkforSSRF(req, res, next);
      expect(next).toHaveBeenCalled(); // Should work after normalization
    });
  });

  describe("Domain Matching Security", () => {
    test("wildcard does not match base domain", () => {
      // *.example.com should NOT match example.com
      const matches = URLValidator.matchesDomain(
        "example.com",
        "*.example.com"
      );
      expect(matches).toBe(false);
    });

    test("no partial matching", () => {
      // "evil.com" should NOT match "notevil.com"
      const matches = URLValidator.matchesDomain("notevil.com", "evil.com");
      expect(matches).toBe(false);
    });
  });

  describe("Complete IP Range Coverage", () => {
    test("blocks multicast addresses", async () => {
      getTargetFields.mockReturnValue([{ value: "http://multicast.test" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "224.0.0.1", family: 4 },
      ]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
    });

    test("blocks complete CGNAT range", async () => {
      getTargetFields.mockReturnValue([{ value: "http://cgnat.test" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "100.127.255.255", family: 4 },
      ]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
    });

    test("blocks broadcast address", async () => {
      getTargetFields.mockReturnValue([{ value: "http://broadcast.test" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "255.255.255.255", family: 4 },
      ]);
      const result = await checkforSSRF(req, res, next);
      expect(result).toBe(false);
    });
  });

  describe("Private IP Blocking - IPv4", () => {
    test("should block localhost - 127.0.0.1", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://localhost-trick.com" },
      ]);
      dns.promises.lookup.mockResolvedValue([
        { address: "127.0.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });

    test("should block 10.0.0.0/8 private range", async () => {
      getTargetFields.mockReturnValue([{ value: "https://internal.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "10.0.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });

    test("should block 192.168.0.0/16 private range", async () => {
      getTargetFields.mockReturnValue([{ value: "https://router.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "192.168.1.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block 172.16.0.0/12 private range - start", async () => {
      getTargetFields.mockReturnValue([{ value: "https://corporate.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "172.16.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block 172.16.0.0/12 private range - middle", async () => {
      getTargetFields.mockReturnValue([{ value: "https://corporate.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "172.20.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block 172.16.0.0/12 private range - end", async () => {
      getTargetFields.mockReturnValue([{ value: "https://corporate.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "172.31.255.255", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block link-local 169.254.0.0/16 (AWS metadata)", async () => {
      getTargetFields.mockReturnValue([{ value: "https://metadata.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "169.254.169.254", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block 0.0.0.0/8 range", async () => {
      getTargetFields.mockReturnValue([{ value: "https://zero.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "0.0.0.0", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block shared address space 100.64.0.0/10", async () => {
      getTargetFields.mockReturnValue([{ value: "https://carrier.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "100.64.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block benchmark testing 198.18.0.0/15", async () => {
      getTargetFields.mockReturnValue([{ value: "https://test.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "198.18.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });
  });

  describe("Private IP Blocking - IPv6", () => {
    test("should block IPv6 localhost ::1", async () => {
      getTargetFields.mockReturnValue([{ value: "https://ipv6-local.com" }]);
      dns.promises.lookup.mockResolvedValue([{ address: "::1", family: 6 }]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });

    test("should block IPv6 unique local fc00::/7", async () => {
      getTargetFields.mockReturnValue([{ value: "https://ipv6-private.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "fc00::1", family: 6 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block IPv6 unique local fd00::/8", async () => {
      getTargetFields.mockReturnValue([{ value: "https://ipv6-private2.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "fd00::1", family: 6 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block IPv6 link-local fe80::/10", async () => {
      getTargetFields.mockReturnValue([{ value: "https://ipv6-link.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "fe80::1", family: 6 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should block IPv4-mapped IPv6 localhost", async () => {
      getTargetFields.mockReturnValue([{ value: "https://mapped.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "::ffff:127.0.0.1", family: 6 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });
  });

  describe("IP Whitelist and Blacklist", () => {
    test("should allow whitelisted public IPs", async () => {
      getTargetFields.mockReturnValue([{ value: "https://google-dns.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "8.8.8.8", family: 4 },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(logger.info).toHaveBeenCalledWith(
        expect.stringContaining("IP whitelist")
      );
    });

    test("should block blacklisted IPs", async () => {
      getTargetFields.mockReturnValue([{ value: "https://suspicious.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "6.6.6.6", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "IP_BLACKLISTED" })
      );
    });

    test("should allow whitelisted IP even if private", async () => {
      fs.promises.readFile.mockImplementation((path) => {
        if (path.includes("whitelistIP")) {
          return Promise.resolve("127.0.0.1\n10.0.0.1");
        }
        if (path.includes("whitelistDomain")) return Promise.resolve("");
        if (path.includes("blacklistDomain"))
          return Promise.resolve("evil.com");
        if (path.includes("allowedProtocols"))
          return Promise.resolve("http\nhttps");
        if (path.includes("blacklistIP")) return Promise.resolve("");
        return Promise.resolve("");
      });

      getTargetFields.mockReturnValue([
        { value: "https://trusted-internal.com" },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("DNS Resolution", () => {
    test("should handle DNS lookup failures", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://non-existent-xyz123.com" },
      ]);
      dns.promises.lookup.mockRejectedValue(new Error("ENOTFOUND"));

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "DNS_FAILED" })
      );
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining("DNS lookup failed")
      );
    });

    test("should handle multiple IP addresses from DNS", async () => {
      getTargetFields.mockReturnValue([{ value: "https://multi-ip.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "93.184.216.34", family: 4 },
        { address: "93.184.216.35", family: 4 },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should block if any resolved IP is private", async () => {
      getTargetFields.mockReturnValue([{ value: "https://mixed-ips.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "93.184.216.34", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });

    test("should allow all public IPs from multiple addresses", async () => {
      getTargetFields.mockReturnValue([{ value: "https://cdn.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "151.101.1.69", family: 4 },
        { address: "151.101.65.69", family: 4 },
        { address: "151.101.129.69", family: 4 },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("Error Handling", () => {
    test("should handle invalid URL formats gracefully", async () => {
      getTargetFields.mockReturnValue([
        { value: "not-a-url-at-all" },
        { value: "ht!tp://broken.com" },
        { value: "://malformed" },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled(); // No valid URLs, allow request
      expect(dns.promises.lookup).not.toHaveBeenCalled();
    });

    test("should handle empty config files", async () => {
      fs.promises.readFile.mockResolvedValue("");
      getTargetFields.mockReturnValue([{ value: "https://example.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should handle config files with only comments", async () => {
      fs.promises.readFile.mockResolvedValue(
        "# comment\n# another comment\n\n"
      );
      getTargetFields.mockReturnValue([{ value: "https://example.com" }]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("Integration Scenarios", () => {
    test("should validate webhook URLs", async () => {
      req.body = { webhookUrl: "https://api.example.com/callback" };
      getTargetFields.mockReturnValue([
        { value: "https://api.example.com/callback" },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should block SSRF to AWS metadata service", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://redirect-to-metadata.com" },
      ]);
      dns.promises.lookup.mockResolvedValue([
        { address: "169.254.169.254", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ code: "PRIVATE_IP" })
      );
    });

    test("should block SSRF to internal services", async () => {
      getTargetFields.mockReturnValue([{ value: "https://internal-api.com" }]);
      dns.promises.lookup.mockResolvedValue([
        { address: "10.0.0.100", family: 4 },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
    });

    test("should handle multiple URLs and fail on first bad one", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://example.com" },
        { value: "https://evil.com" },
        { value: "https://another.com" },
      ]);

      const result = await checkforSSRF(req, res, next);

      expect(result).toBe(false);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: "DOMAIN_BLACKLISTED",
          message: expect.stringContaining("evil.com"),
        })
      );
    });

    test("should allow legitimate external API calls", async () => {
      getTargetFields.mockReturnValue([
        { value: "https://api.github.com/users" },
        { value: "https://api.stripe.com/v1/charges" },
      ]);
      dns.promises.lookup.mockResolvedValue([
        { address: "140.82.121.6", family: 4 },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    test("should validate image upload URLs", async () => {
      req.body = {
        imageUrl: "https://cdn.example.com/images/photo.jpg",
        thumbnailUrl: "https://cdn.example.com/thumbs/photo_thumb.jpg",
      };
      getTargetFields.mockReturnValue([
        { value: "https://cdn.example.com/images/photo.jpg" },
        { value: "https://cdn.example.com/thumbs/photo_thumb.jpg" },
      ]);

      await checkforSSRF(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("Response Format", () => {
    test("should return proper error structure", async () => {
      getTargetFields.mockReturnValue([{ value: "https://evil.com" }]);

      await checkforSSRF(req, res, next);

      expect(res.json).toHaveBeenCalledWith({
        error: "Forbidden",
        message: expect.any(String),
        code: "DOMAIN_BLACKLISTED",
      });
    });

    test("should include failed URL in error", async () => {
      getTargetFields.mockReturnValue([{ value: "https://malicious.net" }]);

      await checkforSSRF(req, res, next);

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("malicious.net")
      );
    });
  });
});
