
const logger = require('../logger/logger');
const Redis = require('ioredis'); 


const redis = new Redis();


const MAX_REQUESTS = 5; // todo -: reduce thsi too much when testing if want a false from this test
const WINDOW_IN_SECONDS = 60; // timer for current window

async function rateLimiter(req) {
  const ip = req.ip; 
  const redisKey = `ratelimitkrrhahu:${ip}`; //unique key for redis
  // increase value in redis map atu this key
  const current = await redis.incr(redisKey);
  console.log(current)
  //IF IT IS FIRST REQUEST
  if (current === 1) {
    // Start a timer
    await redis.expire(redisKey, WINDOW_IN_SECONDS);
    logger.info(`started rate limiting for ip ${ip}, expiry time set is ${WINDOW_IN_SECONDS} seconds.`);
  }

  // block the request
  if (current > MAX_REQUESTS) {
    logger.warn(`rate limit exceeded for ipP ${ip}. current counter: ${current}`);
    return false;
  }

  // allow request
  logger.info(`request from ip ${ip} allowed. Current request count: ${current}`);
  return true;
}

module.exports = rateLimiter;
