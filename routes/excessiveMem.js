const handler = (req , res) => {
    const CYCLE_COUNT = req.body.cycle;
    
    for(let i=0;i<CYCLE_COUNT;i++){
        new Array(1024 * 1024 * 1034);
    }

    res.send({
        output : "cycle is executed"
    })
}

module.exports = handler;