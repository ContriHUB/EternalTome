const os = require('os')
const monitor = (options = {}) => {
      const {
        maxCpuPercent = 90,
        maxMemoryPercent = 80,
        maxMemoryBytes = os.totalmem() * (maxMemoryPercent / 100),
        maxExecutionTime = 60000,
        checkInterval = 1000
      } = options;
      const startTime = Date.now();
      let lastCpuUsage = process.cpuUsage();
    
      
        const currentCpu = process.cpuUsage(lastCpuUsage);
        lastCpuUsage = process.cpuUsage();
        
        
        const elapsedTime = (currentCpu.user + currentCpu.system) / 1000;
        const cpuPercent = (elapsedTime / checkInterval) * 100;
        
        
        const memoryUsage = process.memoryUsage();
        const executionTime = Date.now() - startTime;
        
        
        if (
          cpuPercent > maxCpuPercent ||
          memoryUsage.rss > maxMemoryBytes ||
          executionTime > maxExecutionTime
        ) {
          const mem = memoryUsage.rss;
          return true;
        }
    
    
     
      return false;
    }

  

module.exports = monitor