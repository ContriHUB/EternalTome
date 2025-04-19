// logger.js
const { createLogger, format, transports } = require('winston');

const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.printf(
      ({ timestamp, level, message }) => `[${timestamp}] ${level.toUpperCase()}: ${message}`
    )
  ),
  transports: [
    // new transports.Console(),                         // consoleg print
    new transports.File({ filename: 'security.log' }) // Save to file
  ],
});

module.exports = logger;
