const middle = (req , res , next) => {
    // put the checks here one by one
    
    if(true){
        next();
    }
    else{
        res.status(401).send('Unauthorized!');
    }
}



module.exports = middle;