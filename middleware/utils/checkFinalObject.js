const OWNERSHIP_KEYS = [
  "owner",
  "ownerId",
  "entityId",
  "userId",
  "accountId",
  "tenantId"
];

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

function extractOwnershipMatches(payload) {
  const matches = [];

  function visit(node) {
    if (Array.isArray(node)) {
      for (const element of node) visit(element);
      return;
    }
    if (!isPlainObject(node)) return;

    for (const key of Object.keys(node)) {
      const value = node[key];
      if (OWNERSHIP_KEYS.includes(key)) {
        matches.push(String(value));
      }
      if (isPlainObject(value) || Array.isArray(value)) visit(value);
    }
  }

  visit(payload);
  return matches;
}

function verifyOwnership(req, payload) {
  try {
    const entityId = req && req.headers ? req.headers["x-entity-id"] : undefined;
    if (!entityId) {
      return { ok: false, reason: "Missing entity id in request context" };
    }

    // Attempt to parse strings that look like JSON
    const data = typeof payload === "string" ? safeJsonParse(payload) : payload;

    // Only verify object/array payloads
    if (!isPlainObject(data) && !Array.isArray(data)) {
      return { ok: true };
    }

    const matches = extractOwnershipMatches(data);
    if (matches.length === 0) {
      if (process.env.STRICT_OWNERSHIP === "true") {
        return { ok: false, reason: "No ownership fields present in response" };
      }
      return { ok: true };
    }

    for (const found of matches) {
      if (String(found) !== String(entityId)) {
        return { ok: false, reason: "Ownership mismatch" };
      }
    }

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "Ownership verification error" };
  }
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch (_e) {
    return text;
  }
}

module.exports = { verifyOwnership };