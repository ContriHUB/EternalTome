const handler = (req , res) => {
    const CYCLE_COUNT = req.body.cycle;
    
    for(let i=0;i<CYCLE_COUNT;i++){
        
    }

    res.send({
        output : "cycle is executed"
    })
}

module.exports = handler;