const setTargetFields = (req , updates) => {
    updates.forEach(({ key, value }) => {
        const [scope, field] = key.split('.'); // Split into [scope, field]
        
        switch (scope) {
          case 'query':
            req.query = req.query || {}; // Initialize if undefined
            req.query[field] = value;
            break;
          
          case 'headers':
            req.headers = req.headers || {};
            req.headers[field] = value;
           
            break;
          
          case 'body':
            req.body = req.body || {};
            req.body[field] = value;
            break;
            
          
          case 'cookies':
            req.cookies = req.cookies || {};
            req.cookies[field] = value;
            break;
        case 'params':
            req.params = req.params || {};
            req.params[field] = value;
            break;
          default:
            console.warn(`Unknown scope: ${scope}`);
        }
      });
}

module.exports = setTargetFields