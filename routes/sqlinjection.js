const handler = (req , res) => {
    const username = req.body.username; 
    const password = req.body.password; 


    const unsafeQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    res.send({query : unsafeQuery});
}

module.exports = handler