const mongoose = require('mongoose');
const logger = require('./logger');

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
