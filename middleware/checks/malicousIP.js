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
    console.log(distance);
    return distance;
}

const arr = [
    {
        lat : 28.6670743496496, 
        lon : 77.2308606302525,
        dist : 1600
    }
    
] //get this array dynamically from somewhere
const checkForIpLocation = async (req , res) => {
    const ip = normalizeIP(req.ip);
    const getLocation = await (await fetch(`http://ip-api.com/json/${ip}`)).json();
    if(getLocation.status == 'success'){
        const lat = getLocation.lat;
        const lon = getLocation.lon;

        var flag = true;

        for(let i=0 ; i<arr.length ; i++){
            if(getDist(lat , lon , arr[i].lat , arr[i].lon) > arr[i].dist){
                flag = false;
            }
        }

        if(!flag){
            res.status(401);
            res.send("Ip Location Check Failed");
        }

        return flag;
        

    }
    else{
        return true;
    }
   
}

module.exports = {
    checkForIpLocation
}