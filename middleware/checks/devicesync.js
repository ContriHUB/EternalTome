const logger = require('../logger/logger')
const deviceBlacklisted = [
    "windows"
]

const checkForDevices = ( req , res ) => {
    const userAgent = req.headers['user-agent'] || '';
    const ua = userAgent.toLowerCase();
    var flag = true;
    for(let i=0;i < deviceBlacklisted.length; i++){
        if(ua.includes(deviceBlacklisted[i].toLowerCase())){
            flag = false;
        }
    }
    const ip = req.ip;
    const url = req.url;

    if(!flag){
        logger.warn(`Blocked Device Detected| IP: ${ip} | User-Agent: ${userAgent} | Path: ${url}`);
        res.status(401);
        res.send("Device Type is Not Allowed");
        return false;
    }
    else{
        logger.info(`allowed device| IP: ${ip}| User-Agent: ${userAgent}| Path: ${url}`);
        return true;
    }
}

module.exports = { checkForDevices }