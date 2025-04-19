const fs = require('fs');
const  getBlacklistedIpFromServer = async () => {
    try{
        const res = await  fetch('https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt')
        if(res.status == 200){
            const text = await res.text();
            const lines = text.trim().split(/\r?\n/);
            const remainingLines = lines.slice(7);
            const ips = remainingLines.map(line => line.split(/\s+/)[0]);

            console.log(ips);
            const content = ips.join('\n');

            await fs.writeFile('C:/Users/lokesh/Desktop/hack/Protection/middleware/assets/ipblacklist.txt', content, 'utf8' , () => {

            });
            console.log(content);   
            return;
        }
        else{
            console.log(res);
            return;
        }
       
    }
    catch(err){
        console.log(err);
        return;
    }
    
}

module.exports = getBlacklistedIpFromServer;