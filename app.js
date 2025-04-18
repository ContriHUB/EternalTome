const express = require("express");

const app = express();
const secure = require("./middleware");

app.use(secure);

app.get('/end',(req,res)=>{
    res.send("This the endpoint for performing some attack");
})


app.listen(3000 , () => {

        console.log("Listening on port 3000");
    
})