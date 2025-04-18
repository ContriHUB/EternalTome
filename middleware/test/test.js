const invokeCPP = require("../utils/invokeCPP");

invokeCPP(["apple" , "banana" , "mosambi"] , "C:/Users/lokesh/Desktop/protection/middleware/algorithims/test.exe").then(res =>{
    console.log(res);
})