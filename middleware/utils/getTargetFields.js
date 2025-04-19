const getTargetFields = (req) => {
    try{
        const targets = [
            ...(req.query ? Object.entries(req.query).map(([key, value]) => ({ 
                key: `query.${key}`, 
                value 
            })) : []),
            
            ...(req.body ? Object.entries(req.body).map(([key, value]) => ({ 
                key: `body.${key}`, 
                value 
            })) : []),
            
            ...(req.headers?.['user-agent'] ? [{ 
                key: 'headers.user-agent', 
                value: req.headers['user-agent'] 
            }] : []),
            
            ...(req.headers?.['x-forwarded-for'] ? [{ 
                key: 'headers.x-forwarded-for', 
                value: req.headers['x-forwarded-for'] 
            }] : []),
            
            ...(req.cookies ? Object.entries(req.cookies).map(([key, value]) => ({ 
                key: `cookies.${key}`, 
                value 
            })) : []),
        
            ...(req.params ? Object.entries(req.params).map(([key, value]) => ({ 
                key: `params.${key}`, 
                value 
            })) : []),
        
        ].filter(item => item.value !== undefined && item.value !== null);
       return targets;
    }
    catch(e){
        return [];
    }
}

module.exports = getTargetFields;