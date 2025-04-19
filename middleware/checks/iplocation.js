const logger = require('../logger/logger')
const { normalizeIP } = require('./malicousIP');


const getDist = ( lat1 , lon1 , lat2 , lon2 ) => {
    const R = 6371e3; 
    
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lon2 - lon1) * Math.PI / 180;

    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
              Math.cos(φ1) * Math.cos(φ2) *
              Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

    const distance = R * c;
    // console.log(distance);
    return distance;
}

const arr = [
    {
        lat : 0.0, 
        lon : 77.2308606302525,
        dist : 0
    }
    
] //get this array dynamically from somewhere
const checkForIpLocation = async (req , res) => {
    const ip = normalizeIP(req.ip);
    logger.info(`checking ip : ${ip}`);
    try{
        const getLocation = await (await fetch(`http://ip-api.com/json/${ip}`)).json();
        if(getLocation.status == 'success'){
            const lat = getLocation.lat;
            const lon = getLocation.lon;
            const city = getLocation.city;
            const region = getLocation.region;
            const country = getLocation.country;
            logger.info(`ip location: ${city}, ${region}, ${country} (Lat: ${lat}, Lon: ${lon})`);

            var flag = true;

            for(let i=0 ; i<arr.length ; i++){
                if(getDist(lat , lon , arr[i].lat , arr[i].lon) > arr[i].dist){
                    flag = false;
                }
            }

            if(!flag){
                logger.warn(`ip ${ip} blocked - outside trusted geolocation range`);
                res.status(401);
                res.send("Ip Location Check Failed");
            }

            return flag;
            

        }
        else{
            logger.info(`ip ${ip} passed geolocation checkk`);
            return true;
        }
    }
    catch(err){
        logger.error(`error during ip check: ${error.message}`);
        return true;
    }
   
}

module.exports = {
    checkForIpLocation
}

/* todo -: ask location if in line 69 ip error failed wether we allow it or not
current status allow if ip check failed
*/