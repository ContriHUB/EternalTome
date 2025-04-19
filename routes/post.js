const postHandler = (req , res) => {
    for(let i=0;i<10000000000000;i++){
        new ArrayBuffer(1024 * 1024 * 10); 
    }
    res.send("This is the post endpoint for testing");
}

module.exports = postHandler