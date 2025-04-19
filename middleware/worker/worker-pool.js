const workerpool = require('workerpool');



const pool = workerpool.pool('C:/Users/lokesh/Desktop/n/EternalTome/middleware/worker/worker.js', {
    minWorkers: 4,
    maxWorkers: 6,
    workerType: 'thread',
});




module.exports = pool;