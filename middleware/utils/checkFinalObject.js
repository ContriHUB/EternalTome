const checkFinalObject = (req) => {
    console.log(req.headers ?  req.headers : "No Headers Present");
    console.log(req.cookies ?  req.cookies : "No Cookies Present");
    console.log(req.body ?  req.body : "No Body Present");
}

module.exports = checkFinalObject;