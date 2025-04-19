const logger = require('../logger/logger'); 
const getTargetFields = require("../utils/getTargetFields");
const invokeCPP = require("../utils/invokeCPP");
const setTargetFields = require("../utils/setTargetFields");
const checkForSQLInjection = async (req , res) => {
    try{
       logger.info(`starting sql injection checks`);
       const targets = getTargetFields(req);
     
       const unsanitizedFields = targets.map((obj , idx) => {
        return obj.value;
       })
       const sanitizedFields = await invokeCPP(unsanitizedFields , "C:/Users/lokesh/Desktop/hack/Protection/middleware/algorithims/sqlinjection.exe");
       
       for(let i=0;i<targets.length;i++){
        targets[i].value = sanitizedFields[i];
       }
       
       for(let i=0;i<targets.length;i++){
        req[targets[i].key] = targets[i].value;
       }
       
       setTargetFields(req , targets);
       logger.info("SQL injection check completed request is ok!!");
       
    }
    catch(e){
        logger.error(`sql injection check failed: ${e.message}`);
    }
    
} 

module.exports = checkForSQLInjection;