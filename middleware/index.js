const checkForSQLInjection = require("./checks/sqlinjection");
const getBlackListedIp = require("./utils/getBlacklistedIpFromServer");
const { checkforMalicousIP } = require('./checks/malicousIP');
const { checkForIpLocation } = require('./checks/iplocation');
const { checkForDevices } = require('./checks/devicesync');

const pool = require('./worker/worker-pool')

const TEN_HOURS = 10 * 60 * 60 * 1000;
const secure = async (req , res , next) => {
    // const originalSend = res.send;
    // res.send = function(body) {
    //     //post checks
    //     if(true){

    //         // do post check here


    //       orignalSend.call(this , body);  
    //     }
    //     else{
    //         originalSend.call(this , "API format is broken");
    //     }
        
        
    // };
  
   
    if(true){
        // prechecks
        
        setInterval(getBlackListedIp , TEN_HOURS);
        // await checkForSQLInjection(req,res);
        const malicousIpCheck = await checkforMalicousIP(req,res);
        const ipLocationCheck = await checkForIpLocation(req,res);
        const deviceTypeCheck = checkForDevices(req,res);
        
        if(malicousIpCheck && ipLocationCheck && deviceTypeCheck){
            next();
        }
        
    }
    else{
        res.status(401).send('Unauthorized!');
    }
}


const container = async (req , res , handler) => {
    
    try{

        pool.exec('processRequest', [{body : req.body , query : req.query , cookies : req.cookies} , handler] , {
            on: ({name , payload}) => {
               
                switch (name){
                    case 'send':
                        res.send(payload.data);
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
                        if (payload.statusCode) {
                            res.redirect(payload.statusCode, payload.url);
                        } else {
                            res.redirect(payload.url);
                        }
                        break;
                        
                    case 'download':
                        if (payload.options) {
                            res.download(payload.filePath, payload.filename, payload.options);
                        } else if (payload.filename) {
                            res.download(payload.filePath, payload.filename);
                        } else {
                            res.download(payload.filePath);
                        }
                        break;
                        
                    case 'sendFile':
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
                        
                    default:
                        console.warn(`Unknown worker event: ${name}`);
                        break;
                }
    
            }
        })
    }
    catch(e){
        console.log(e);
    }
    
}

module.exports = { secure , container}