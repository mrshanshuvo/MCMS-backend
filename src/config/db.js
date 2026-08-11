const mongoose = require('mongoose');
const dns = require('dns');
const logger = require('./logger');

// Set public DNS servers fallback for Windows SRV queries
try {
  dns.setServers(['8.8.8.8', '1.1.1.1']);
} catch {
  // Ignore DNS setServers error if not supported in environment
}

const MONGODB_URI =
  process.env.MONGODB_URI ||
  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.ezlz7xu.mongodb.net/medicalDB?retryWrites=true&w=majority&appName=Cluster0`;

async function connectDB() {
  if (mongoose.connection.readyState === 1) {
    logger.info('MongoDB already connected.');
    return;
  }

  await mongoose.connect(MONGODB_URI);
  logger.info('Successfully connected to MongoDB via Mongoose.');
}

module.exports = {
  connectDB,
  dbConnection: mongoose.connection,
};
