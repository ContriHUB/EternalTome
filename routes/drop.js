const pool = require('../middleware/worker/worker-pool')
const handler = (req , res) => {
    pool.terminate({timeout : 3000});
    res.send("Terminated the Threads");
}

module.exports = handler