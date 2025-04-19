const handler = (req , res) => {
    const url = req.body.redirectLink;


    // const unsafeQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    res.send({output : `Sucessfully Injected Payload from ${url}`});
}

module.exports = handler