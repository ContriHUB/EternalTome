const checkForSQLInjection = require("./checks/sqlinjection");
const getBlackListedIp = require("./utils/getBlacklistedIpFromServer");
const { checkforMalicousIP } = require('./checks/malicousIP');
const { checkForIpLocation } = require('./checks/iplocation');
const { checkForDevices } = require('./checks/devicesync');
const { isSessionValid, storeSession } = require('./checks/sessionmanager');
const jwt = require('jsonwebtoken');
const checkForSSRF = require('./checks/serversideforgery');
const pool = require('./worker/worker-pool');

const TEN_HOURS = 10 * 60 * 60 * 1000;
const EventEmitter = require('events');
const rateLimiter = require("./checks/ratelimit");
const logger = require("./logger/logger");
const checkFormat = require("./trafficcontrol/formatcheck");

const Joi = require('joi');
const redisClient = require("./utils/redisclient");
const bcrypt = require('bcrypt');

var BASE_MEMORY = 0;
const secretKey = "this is a secret key rsa oooo very scary";
const options = {
  MEMORY_LIMIT_MB: 120,
  CHECK_INTERVAL_MS: 5000,
  MAX_TIME: 4000,
};

const events = new EventEmitter();

// ----------------------------------
// Memory monitoring
// ----------------------------------
const monitorMemory = () => {
  const memoryUsage = process.memoryUsage();
  const currMem = (memoryUsage.rss / 1024 / 1024) - BASE_MEMORY;

  console.log("current mem consumption is " + currMem);
  if (currMem > options.MEMORY_LIMIT_MB) {
    logger.warn(`Memory Limit Has been Exceedded with current consumption being ${currMem}`);
    pool.terminate(true);
    events.emit('terminate');
  }
};

setInterval(() => monitorMemory(), options.CHECK_INTERVAL_MS);
setInterval(getBlackListedIp, TEN_HOURS);

// ----------------------------------
// API schema
// ----------------------------------
const apiSchema = {
  "/get/": Joi.object({ data: Joi.string() }),
  "/post/": Joi.object({
    data: Joi.string(),
    port: Joi.number()
  }),
  "/sqlinjection/": Joi.object({
    query: Joi.string()
  }),
  "/serversideforgery/": Joi.object({
    output: Joi.string()
  }),
  "/excessiveMem/": Joi.object({
    output: Joi.string()
  }),
  "/excessiveTime/": Joi.object({
    output: Joi.string()
  }),
};

// ----------------------------------
// Helpers
// ----------------------------------
const decryptToken = (token, secret) => jwt.verify(token, secret);

function ensureTrailingSlash(str) {
  if (!str) return '/';
  return str.endsWith('/') ? str : str + '/';
}

// ----------------------------------
// PRECHECKS middleware
// ----------------------------------
const prechecks = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const payload = decryptToken(token, secretKey);
  req.headers['x-entity-id'] = payload.entityId;

  const validSession = await isSessionValid(req);
  if (!validSession) {
    const rateResult = await rateLimiter(req);
    if (!rateResult.allowed) {
      res.setHeader("X-RateLimit-Limit", rateResult.limit);
      res.setHeader("X-RateLimit-Remaining", rateResult.remaining);
      res.setHeader(
        "X-RateLimit-Reset",
        new Date(rateResult.resetTime).toISOString()
      );

      return res.status(429).json({
        error: "Too Many Requests",
        message: `Rate limit exceeded. Try again after ${new Date(
          rateResult.resetTime
        ).toISOString()}`,
        retryAfter: Math.ceil((rateResult.resetTime - Date.now()) / 1000),
      });
    }
  }

  await checkForSQLInjection(req, res);
  if (res.headersSent) return;

  await checkForSSRF(req, res);
  if (res.headersSent) return;

  await checkforMalicousIP(req, res);
  if (res.headersSent) return;

  await checkForIpLocation(req, res);
  if (res.headersSent) return;

  await checkForDevices(req, res);
  if (res.headersSent) return;

  next();
};

// ----------------------------------
// CONTAINER function
// ----------------------------------
const container = async (req, res, handler) => {
  try {
    var flag = false;

    const id = setTimeout(() => {
      if (flag) return;
      res.status(400);
      res.send({ error: "Resource usage exceeded", errorPayload: true });
      flag = true;
    }, options.MAX_TIME);

    events.on('terminate', () => {
      if (flag) return;
      res.status(400);
      res.send({ error: "Resource usage exceeded", errorPayload: true });
      flag = true;
    });

    pool.exec('processRequest', [{ body: req.body, query: req.query, cookies: req.cookies, headers: req.headers }, handler], {
      on: ({ name, payload }) => {
        if (flag) return;

        switch (name) {
          case 'send':
            flag = true;
            res.send(payload.data);
            clearTimeout(id);
            break;
          case 'json':
            res.json(payload.data);
            break;
          case 'status':
            res.status(payload.code);
            break;
          case 'end':
            res.end();
            break;
          case 'set':
            res.set(payload.key, payload.value);
            break;
          case 'type':
            res.type(payload.contentType);
            break;
          case 'redirect':
            flag = true;
            if (payload.statusCode) {
              res.redirect(payload.statusCode, payload.url);
            } else {
              res.redirect(payload.url);
            }
            break;
          case 'download':
            flag = true;
            if (payload.options) {
              res.download(payload.filePath, payload.filename, payload.options);
            } else if (payload.filename) {
              res.download(payload.filePath, payload.filename);
            } else {
              res.download(payload.filePath);
            }
            break;
          case 'sendFile':
            flag = true;
            if (payload.options) {
              res.sendFile(payload.filePath, payload.options);
            } else {
              res.sendFile(payload.filePath);
            }
            break;
          case 'cookie':
            res.cookie(payload.name, payload.value, payload.options);
            break;
          case 'clearCookie':
            res.clearCookie(payload.name, payload.options);
            break;
          case 'location':
            res.location(payload.url);
            break;
          case 'vary':
            res.vary(payload.field);
            break;
          case 'append':
            res.append(payload.field, payload.value);
            break;
          case 'error':
            console.error('Worker Error:', payload.error);
            res.status(payload.status || 500).send(payload.message || 'Internal Server Error');
            break;
          case 'exit':
            res.status(400);
            if (payload.code == 1) {
              res.send("Too many resource consumed");
            } else {
              res.send("Worker was terminated");
            }
            break;
          default:
            console.log(`Unknown worker event: ${name}`);
            break;
        }
      }
    });

  } catch (e) {
    console.log(e);
  }
};

// ----------------------------------
// TOKEN GENERATOR
// ----------------------------------
const generateToken = async (req, res) => {
  try {
    const password = req.query.password;
    const entityId = req.query.entityId;

    if (!password || !entityId) {
      return res.status(400).json({ error: 'Password and entityId are required' });
    }

    const redisKey = entityId.toString();
    const keyExists = (await redisClient.exists(redisKey)) === 1;

    if (keyExists) {
      const hashedPassword = await redisClient.get(redisKey);
      const isMatch = await bcrypt.compare(password, hashedPassword);

      if (isMatch) {
        const token = jwt.sign(
          { entityId: entityId },
          secretKey,
          { expiresIn: '24h' }
        );

        return res.status(200).json({
          message: 'Authentication successful',
          token: token,
          expiresIn: 3600
        });
      } else {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      await redisClient.set(redisKey, hashedPassword, {
        EX: 86400
      });

      const token = jwt.sign(
        { entityId: entityId },
        secretKey,
        { expiresIn: '1h' }
      );

      return res.status(201).json({
        message: 'New credentials stored',
        token: token,
        expiresIn: 3600
      });
    }
  } catch (error) {
    console.error('Error in generateToken:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// ----------------------------------
// POSTCHECKS middleware (with ownership verification)
// ----------------------------------
const postChecks = (req, res, next) => {
  const oldSend = res.send.bind(res);
  const requesterId = String(req.headers['x-entity-id'] ?? '').trim();
  const OWNER_KEYS = new Set(['owner', 'ownerid', 'entityid', 'createdby', 'userid']);

  const findOwnerField = (obj, depth = 0) => {
    if (obj == null || depth > 6) return null;
    if (Array.isArray(obj)) {
      for (const el of obj) {
        const res = findOwnerField(el, depth + 1);
        if (res) return res;
      }
      return null;
    }
    if (typeof obj === 'object') {
      for (const key of Object.keys(obj)) {
        const val = obj[key];
        const low = key.toLowerCase();
        if (OWNER_KEYS.has(low)) {
          const foundVal = String(val ?? '').trim();
          return { found: true, matches: (foundVal === requesterId), key: key, value: foundVal };
        }
        if (typeof val === 'object' && val !== null) {
          const nested = findOwnerField(val, depth + 1);
          if (nested) return nested;
        }
      }
    }
    return null;
  };

  res.send = (data) => {
    try {
      if (data && data.errorPayload) {
        return oldSend(data.error);
      }

      const path = ensureTrailingSlash(req.path);
      if (!checkFormat(data, apiSchema[path])) {
        res.status(400);
        return oldSend("Wrong Format");
      }

      if (data && typeof data === 'object') {
        const ownerCheck = findOwnerField(data);
        if (ownerCheck && ownerCheck.found && !ownerCheck.matches) {
          res.status(403);
          return oldSend(JSON.stringify({ error: "Forbidden: resource not owned by you" }));
        }
      }

      return oldSend(JSON.stringify(data));
    } catch (e) {
      console.error('postChecks middleware error:', e);
      res.status(500);
      return oldSend('Internal Server Error');
    }
  };

  next();
};

// ----------------------------------
// EXPORTS
// ----------------------------------
module.exports = { prechecks, container, generateToken, postChecks };
