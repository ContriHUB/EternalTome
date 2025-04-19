const handler  = (req , res) => {

    res.status(200);
    res.send({ data : "req.entity"});
}

module.exports = handler