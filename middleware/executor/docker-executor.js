// executor/docker-executor.js
const Docker = require("dockerode");
const EventEmitter = require("events");
const logger = require("../logger/logger");

class DockerExecutor extends EventEmitter {
  constructor(config) {
    super();
    this.docker = new Docker();
    this.config = config;
    this.activeContainers = new Map();
    this.warmPool = [];
    this.initWarmPool();
  }

  async initWarmPool() {
    if (!this.config.docker.reuseContainers) return;

    for (let i = 0; i < this.config.docker.warmPoolSize; i++) {
      try {
        const container = await this.createContainer();
        this.warmPool.push(container);
      } catch (error) {
        logger.error("Failed to create warm container:", error);
      }
    }
  }

  async createContainer() {
    const containerConfig = {
      Image: this.config.docker.image,
      Cmd: ["node", "/app/worker.js"],
      HostConfig: {
        Memory: this.parseMemoryLimit(this.config.docker.memoryLimit),
        NanoCpus: this.parseCpuLimit(this.config.docker.cpuLimit),
        NetworkMode: this.config.docker.networkMode,
        AutoRemove: this.config.docker.removeOnExit,
        ReadonlyRootfs: true,
        Tmpfs: {
          "/tmp": "rw,noexec,nosuid,size=65536k",
        },
      },
      Volumes: {
        "/app": {},
      },
      WorkingDir: "/app",
    };

    const container = await this.docker.createContainer(containerConfig);
    return container;
  }

  async execute(req, handler) {
    return new Promise(async (resolve, reject) => {
      let container = null;
      const timeout = setTimeout(() => {
        this.cleanup(container);
        reject(new Error("Container execution timeout"));
      }, this.config.docker.timeout);

      try {
        // Get container from pool or create new
        container = this.warmPool.pop() || (await this.createContainer());

        // Start container
        await container.start();

        // Prepare execution payload
        const payload = JSON.stringify({
          request: {
            body: req.body,
            query: req.query,
            cookies: req.cookies,
            headers: req.headers,
          },
          handler: handler,
        });

        // Execute in container
        const exec = await container.exec({
          Cmd: ["node", "-e", this.generateExecutionScript(payload)],
          AttachStdout: true,
          AttachStderr: true,
        });

        const stream = await exec.start();
        let output = "";
        let error = "";

        stream.on("data", (chunk) => {
          const str = chunk.toString();
          if (str.includes("ERROR:")) {
            error += str;
          } else {
            output += str;
          }
        });

        stream.on("end", async () => {
          clearTimeout(timeout);

          if (error) {
            await this.cleanup(container);
            reject(new Error(error));
          } else {
            try {
              const result = JSON.parse(output);
              await this.returnToPool(container);
              resolve(result);
            } catch (e) {
              await this.cleanup(container);
              reject(new Error("Failed to parse container output"));
            }
          }
        });
      } catch (error) {
        clearTimeout(timeout);
        await this.cleanup(container);
        reject(error);
      }
    });
  }

  generateExecutionScript(payload) {
    return `
      const payload = ${payload};
      const handler = require(payload.handler);
      const results = [];
      
      const mockRes = {
        send: (data) => results.push({ type: 'send', data }),
        json: (data) => results.push({ type: 'json', data }),
        status: (code) => { results.push({ type: 'status', code }); return mockRes; },
        end: () => results.push({ type: 'end' })
      };
      
      try {
        handler(payload.request, mockRes);
        console.log(JSON.stringify(results));
      } catch (error) {
        console.error('ERROR:', error.message);
      }
    `;
  }

  async returnToPool(container) {
    if (
      this.config.docker.reuseContainers &&
      this.warmPool.length < this.config.docker.warmPoolSize
    ) {
      try {
        await container.stop();
        this.warmPool.push(container);
        return;
      } catch (error) {
        logger.warn("Failed to return container to pool:", error);
      }
    }
    await this.cleanup(container);
  }

  async cleanup(container) {
    if (!container) return;

    try {
      await container.stop();
      if (!this.config.docker.removeOnExit) {
        await container.remove();
      }
    } catch (error) {
      logger.warn("Container cleanup error:", error);
    }
  }

  parseMemoryLimit(limit) {
    const match = limit.match(/^(\d+)(m|g)$/i);
    if (!match) return 256 * 1024 * 1024; // Default 256MB

    const value = parseInt(match[1]);
    const unit = match[2].toLowerCase();
    return unit === "g" ? value * 1024 * 1024 * 1024 : value * 1024 * 1024;
  }

  parseCpuLimit(limit) {
    // Convert CPU limit (e.g., "0.5") to NanoCPUs
    return parseFloat(limit) * 1e9;
  }

  async shutdown() {
    // Clean up warm pool
    for (const container of this.warmPool) {
      await this.cleanup(container);
    }
    this.warmPool = [];
  }
}

module.exports = DockerExecutor;
