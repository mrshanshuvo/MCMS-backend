require('dotenv').config();
const { validateEnv } = require('./config/env');
const logger = require('./config/logger');

// Validate environment variables before boot
validateEnv();

const { connectDB, client } = require('./config/db');
const app = require('./app');

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    await connectDB();
    const server = app.listen(PORT, () => {
      logger.info(`Server successfully started on port ${PORT}`);
    });

    const gracefulShutdown = (signal) => {
      logger.warn(`Received ${signal}. Shutting down gracefully...`);
      server.close(async () => {
        logger.info('HTTP server closed.');
        try {
          await client.close();
          logger.info('MongoDB connection closed.');
          process.exit(0);
        } catch (err) {
          logger.error(`Error closing MongoDB connection: ${err.message}`);
          process.exit(1);
        }
      });
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
}

startServer();
