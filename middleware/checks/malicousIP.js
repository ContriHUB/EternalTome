const logger = require('../logger/logger');
const fs = require('fs');

const normalizeIP = (ip) => {
    if (ip === "::1") return "127.0.0.1";
    if (ip.startsWith("::ffff:")) return ip.split("::ffff:")[1];
    return ip;
};

const checkforMalicousIP = (req , res) => {
    let ip = normalizeIP(req.ip);
    logger.info(`checking ip: ${ip}`);
    try {
        const data = fs.readFileSync("C:/Users/lokesh/Desktop/n/EternalTome/middleware/assets/ipblacklist.txt", "utf-8");
        const blacklist = data.split("\n").map(ip => ip.trim()).filter(ip => ip);

        for (let i = 0; i < blacklist.length; i++) {
            if (blacklist[i] === ip) {
                logger.warn(`blocked malicious ip: ${ip}`);
                res.status(401).send("Malicious IP detected");
                return false;
            }
        }

        logger.info(`ip ${ip} is clean check passed`);
        return true;
    } catch (error) {
        logger.error(`error during ip check: ${error.message}`);
        return true; //wether we allow it or not
    }
}

module.exports = { checkforMalicousIP , normalizeIP };
