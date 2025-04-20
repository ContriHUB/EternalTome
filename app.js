const express = require("express");

const app = express();
const { prechecks , container, generateToken, postChecks} = require("./middleware");
const cookieParser = require('cookie-parser');
const { compareSync } = require("bcrypt");



app.set("trust proxy", true); // if sitting behind a proxy
app.use(express.json()); // if using req.body
app.use(cookieParser());// if using cookies


app.get('/token',generateToken);
app.use(prechecks);
app.use(postChecks);


app.post('/post',(req,res) => {
    container(req , res , 'post.js')
})

app.get('/get' , (req , res)=>{
    container(req , res , 'get.js')
  
})

app.post('/sqlinjection' , (req , res) => {
    container(req , res , 'sqlinjection.js')
    
})

app.post('/serversideforgery' , (req , res) => {
    container(req , res , 'serversideforgery.js');
})

app.post('/excessiveMem' , (req , res) => {
    container(req , res , 'excessiveMem.js');
})

app.post('/excessiveTime' , (req , res) => {
    container(req , res , 'excessiveTime.js')
});

app.listen(3000 , () => {

        console.log("Listening on port 3000");
    
})