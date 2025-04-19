// utils/sessionmanager.js is file path trololo
const crypto = require('crypto');
const redisClient = require('./redisclient');

const SESSION_TTL = 60 * 60; // 1 hour -> increase it a little bit like 1 months or some

// creating a session hash
function generateSessionHash(req) {
  const ip = req.ip || ''; //if ip is not present then should we generate hash with empty string, random string, or reject decide on this in hack 36
  const jwt = (req.headers['authorization'] || ''); //jwt token in authorization header, again decide what to do if not present (currently empty string is used here)
  const userAgent = req.headers['user-agent'] || '';//mozilla firefox when mozilla icedog enters

  const rawData = `${ip}|${jwt}|${userAgent}`; 
  const hash = crypto.createHash('sha256').update(rawData).digest('hex');

  return `session:${hash}`;
}

//if hash already present
async function isSessionValid(req) {
  const hashKey = generateSessionHash(req);
  const exists = await redisClient.exists(hashKey);
  return exists === 1;
}

//store session in redis with decide ttl above make it 0 to logout everytime website close 
async function storeSession(req) {
  const hashKey = generateSessionHash(req);
  await redisClient.setEx(hashKey, SESSION_TTL, '1');
}

module.exports = {
  isSessionValid,
  storeSession
};
