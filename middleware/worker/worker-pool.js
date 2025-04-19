const workerpool = require('workerpool');



const pool = workerpool.pool('C:/Users/lokesh/Desktop/hack/Protection/middleware/worker/worker.js', {
    minWorkers: 4,
    maxWorkers: 6,
    workerType: 'thread',
});




module.exports = pool;