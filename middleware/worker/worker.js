const workerpool = require('workerpool');
const os = require('os');
const { threadId } = require('worker_threads');
const monitor = require('./worker-monitor');

  
  

async function processRequest(req ,path) {
    const handler = require('C:/Users/lokesh/Desktop/hack/Protection/routes/'  + path);
    
    const emit = (eventName, payload) => {
        workerpool.workerEmit({ name: eventName, payload: payload });
    };
  
    const mockRes = {

        send: (data) => emit('send', { data }),
        json: (data) => emit('json', { data }),
        end: () => emit('end', {}),

        status: (code) => {
            emit('status', { code });
            return mockRes; 
        },


        set: (key, value) => emit('set', { key, value }),
        header: (key, value) => emit('set', { key, value }), 
        type: (contentType) => emit('type', { contentType }),


        redirect: (statusOrUrl, url) => {
            if (typeof statusOrUrl === 'number') {
            emit('redirect', { statusCode: statusOrUrl, url });
            } else {
            emit('redirect', { url: statusOrUrl });
            }
            return mockRes;
        },


        download: (filePath, filename, options) => 
            emit('download', { filePath, filename, options }),
        sendFile: (filePath, options) => 
            emit('sendFile', { filePath, options }),


        cookie: (name, value, options) => 
            emit('cookie', { name, value, options }),
        clearCookie: (name, options) => 
            emit('clearCookie', { name, options }),


        location: (url) => emit('location', { url }),
        vary: (field) => emit('vary', { field }),
        append: (field, value) => emit('append', { field, value }),

    };
    
     
    
  
    handler(req, mockRes);
   
}


workerpool.worker({ processRequest });