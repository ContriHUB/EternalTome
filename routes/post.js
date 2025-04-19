const postHandler = (req , res) => {
    // for(let i=0;i<10000000000000;i++){
    //     new ArrayBuffer(1024 * 1024 * 10); 
    // }
    res.send({
        data : "endpoint is correct",
        port: 3311
    });
}

module.exports = postHandler