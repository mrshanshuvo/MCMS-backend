require('dotenv').config();
const { connectDB } = require('../config/db');

async function seedIndexes() {
  try {
    console.log('Connecting to database...');
    await connectDB();
    console.log('Database indexes successfully created and verified.');
    process.exit(0);
  } catch (error) {
    console.error('Index creation failed:', error);
    process.exit(1);
  }
}

seedIndexes();
