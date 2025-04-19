const checkForSQLInjection = require("./checks/sqlinjection");
const getBlackListedIp = require("./utils/getBlacklistedIpFromServer");
const { checkforMalicousIP } = require('./checks/malicousIP');
const { checkForIpLocation } = require('./checks/iplocation');
const { checkForDevices } = require('./checks/devicesync');
const {isSessionValid, storeSession} = require('./checks/sessionmanager');
const jwt = require('jsonwebtoken');const checkForSSRF = require('./checks/serversideforgery');

const pool = require('./worker/worker-pool')


const TEN_HOURS = 10 * 60 * 60 * 1000;
const EventEmitter = require('events');
const rateLimiter = require("./checks/ratelimit");
const logger = require("./logger/logger");
const checkFormat = require("./trafficcontrol/formatcheck");


const Joi = require('joi');
const redisClient = require("./utils/redisclient");
const bcrypt = require('bcrypt');

var BASE_MEMORY = process.memoryUsage().rss / 1024 / 1024;
const secretKey = "this is a secret key rsa oooo very scary";
const options = {
  MEMORY_LIMIT_MB : 20, // 500MB limit
  CHECK_INTERVAL_MS : 5000, // Check every 5 seconds
  MAX_TIME : 4000,
}
BASE_MEMORY = process.memoryUsage().rss / 1024 / 1024;
const events = new EventEmitter();


const monitorMemory = () => {
  const memoryUsage = process.memoryUsage();
  const currMem = (memoryUsage.rss / 1024 / 1024) - BASE_MEMORY; // Resident Set Size in MB

//   console.log("current mem consumption is " + currMem);
  if (currMem  > options.MEMORY_LIMIT_MB) {
    logger.warn(`Memory Limit Has been Exceedded with current consumption being ${currMem}`);
    // console.log("terminating");
    // BASE_MEMORY = process.memoryUsage().rss / 1024 / 1024;
    pool.terminate(true);
    events.emit('terminate');
  }

  
}

setInterval(()=> {
    monitorMemory();
} , options.CHECK_INTERVAL_MS);

setInterval(getBlackListedIp , TEN_HOURS);

const apiSchema = {//
    // endpoint to joi object 
    // used to validate
    "/get/" : Joi.object({ data : Joi.string() }),
    "/post/" : Joi.object( {
        data : Joi.string(),
        port : Joi.number()
    }),
    "/sqlinjection/" : Joi.object({
        query : Joi.string()
    }),
    "/serversideforgery/" : Joi.object({
        output : Joi.string()
    }),
    "/excessiveMem/" : Joi.object({
        output : Joi.string()
    }),
    "/excessiveTime/" : Joi.object({
        output : Joi.string()
    }),
}

// each object has to have a uniquely identifying key
// each key is to be assoicated with a owne
// owner auth to be done
const decryptToken = (token , secret) => {
    return jwt.verify(token, secret);
}



const prechecks = async (req , res , next) => {
    // const originalSend = res.send;
    
    const token = req.headers.authorization?.split(' ')[1]; // Assuming "Bearer <token>"

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    
    const payload = decryptToken(token  , secretKey);
    req.headers['x-entity-id'] = payload.entityId;
   

    const validSession = await isSessionValid(req);
    var rateLimited = false;
    if(validSession){
        rateLimited = await rateLimiter(req); 
    }

    if(validSession && !rateLimited){
        res.status(400);
        res.send("This end point has been RateLimited");
        return;
    }

    
 
  
    if(true){
        // prechecks
        
        // 
        await checkForSQLInjection(req,res);
        const malicousIpCheck = await checkforMalicousIP(req,res);
        const ipLocationCheck = await checkForIpLocation(req,res);
        const deviceTypeCheck = checkForDevices(req,res);
        const ssrfCheck = await checkForSSRF(req, res);
        
        if(ssrfCheck && deviceTypeCheck && malicousIpCheck && ipLocationCheck){
            next();
           
        }
        

       
        
    }
    else{
        res.status(401).send('Unauthorized!');
    }
}


const container = async (req , res , handler) => {
  
    try{
        var flag = false;
       
            const id = setTimeout(() => {
                if(flag){
                    return;
                }
                res.status(400);
                res.send({error : "Resource usage exceeded" , errorPayload : true});
                flag = true;
            }, options.MAX_TIME);
    
            events.on('terminate' , ()=>{
                if(flag){
                    return;
                }
                res.status(400);
                res.send({error : "Resoruce usage exceeded" , errorPayload : true});
                flag = true;
            })
    
        

        pool.exec('processRequest', [{body : req.body , query : req.query , cookies : req.cookies , headers : req.headers} , handler] , {
            on: ({name , payload}) => {
                // console.log(name);
                if(flag){
                    return;
                }
                switch (name){
                    
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
                        if(payload.code == 1){
                            res.send("Too many resource consumed");
                        }
                        else{
                            res.send("Worker was terminated");
                        }
                        break;
                    default:
                        console.log(`Unknown worker event: ${name}`);
                        break;
                }
                return;
            }
        })
        
    }
    catch(e){
        console.log(e);
    }
    
}


var count = 0;


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
            // Key exists - verify password
            const hashedPassword = await redisClient.get(redisKey);
            
            const isMatch = await bcrypt.compare(password, hashedPassword);
            if (isMatch) {
                // Password matches - generate JWT token
                const token = jwt.sign(
                    { entityId: entityId },
                    secretKey, // Store this in your environment variables
                    { expiresIn: '24h' } // Token expires in 1 hour
                );

                return res.status(200).json({ 
                    message: 'Authentication successful',
                    token: token,
                    expiresIn: 3600 // 1 hour in seconds
                });
            } else {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            // Key doesn't exist - store new hashed password
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            
            // Store in Redis with expiration (1 day)
            await redisClient.set(redisKey, hashedPassword, {
                EX: 86400
            });

            // Generate token for new user
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


function ensureTrailingSlash(str) {
   
    if (!str) return '/';
    

    if (str.endsWith('/')) {
      return str;
    }
    
  
    return str + '/';
  }

const postChecks = (req , res , next) => {
    const oldSend = res.send;
    
    res.send = (data) => {
        // console.log(data.length);
        // console.log(count);
        // count++;
        // console.log(JSON.stringify(data));
        // console.log(req.path);
        if(data.errorPayload){
            console.log(data);
            // oldSend.call(res , data.error);
            oldSend.call(res , data.error);
        }
        else{
            const path = ensureTrailingSlash(req.path);
            console.log(path);
            if( checkFormat(data , apiSchema[path])){
                // console.log('(');
                oldSend.call(res , JSON.stringify(data));
            }
            else{
                res.status(400);
                oldSend.call(res , "Wrong Format");
            }
        }
       
        
    }
    next();
    
}
module.exports = { prechecks , container , generateToken , postChecks}
