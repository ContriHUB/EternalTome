const logger = require('../logger/logger');
const getTargetFields = require('../utils/getTargetFields');
const {URL}=require('url')
const dns = require('dns').promises;
const fs = require('fs');

function isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (err) {
      return false;
    }
  }


async function checkUrl(urlString,res,whitelist,blacklist){
    
   
    
    for (let i = 0; i < whitelist.length;i++){
        const curr_domain = whitelist[i];
        if(urlString.includes(curr_domain)){
            return true;
        }
    }
    
    for (let i = 0; i < blacklist.length;i++){
        const curr_domain = blacklist[i];
        if(urlString.includes(curr_domain)){
            logger.warn("Blacklisted url found, cannot forward request");
            res.status(400).send("Url is blacklisted.");
            return false;
        }
    }
    
    const url = new URL(urlString);
    
    // DNS resolution
    const addresses = await dns.lookup(url.hostname, { all: true });

    // Block private IP ranges
    for (const addr of addresses) {
      const ip = addr.address;
      if (
        ip.startsWith('127.') || // localhost
        ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        ip.startsWith('169.254.') ||
        ip.startsWith('0.') ||
        ip === '::1' || // IPv6 localhost
        ip.startsWith('fc') || ip.startsWith('fd') // IPv6 local
      ) {
          logger.warn("Cannot forward requests from this URL");
          res.status(400).send("Cannot forward requests from this URL");
          return false;
      }
    }
    
    return true;
}

const checkforSSRF = async (req, res) => {
    const targets = getTargetFields(req);
    // console.log(targets);
    const unsanitizedFields = targets.map((obj) => {
        if(isValidUrl(obj.value)){
            return obj.value;
        }
       
    }).filter((val)=>{
        if(val == null){
            return false;
        }
        return true;
    });
    const white_data=fs.readFileSync("C:/Users/lokesh/Desktop/n/EternalTome/middleware/assets/whitelistDomain.txt", "utf-8");
    const whitelist = white_data.split("\n").map(ip => ip.trim()).filter(ip => ip);
    const black_data=fs.readFileSync("C:/Users/lokesh/Desktop/n/EternalTome/middleware/assets/blacklistDomain.txt", "utf-8");
    const blacklist = black_data.split("\n").map(ip => ip.trim()).filter(ip => ip);
    console.log(unsanitizedFields);
    try {
        const data = fs.readFileSync("C:/Users/lokesh/Desktop/n/EternalTome/middleware/assets/allowedProtocols.txt", "utf8");
        const allowedProtocols = data.split('\n');
        
        let flag = false;
        
        for (let i = 0; i < unsanitizedFields.length;i++){
            const url = unsanitizedFields[i];
                // console.log(url);
                for (let j = 0; j < allowedProtocols.length;j++){
                    if(url.includes(allowedProtocols[j])){
                        flag = true;
                        const isSafe=await checkUrl(url,res,whitelist,blacklist)
                        if(!isSafe){
                            return false;
                        }
                    }
                }
            
                
            }
        if(flag){
            logger.warn("Unsupported url protocol found, cannot forward request");
            res.status(400).send("Url with unsupported protocol found.");
            return false;
        }
        // res.status(200).send("Url is good to go!");
        
        return true;
        } catch (error){
            logger.error(`check for server side forgery failed : ${error.message}`);
            res.status(500).send("internal server error"); 
            return false;
        }
};

module.exports = checkforSSRF;