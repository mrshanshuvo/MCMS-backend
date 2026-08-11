require('dotenv').config();
const bcrypt = require('bcryptjs');
const { connectDB, dbConnection } = require('../config/db');
const User = require('../modules/users/users.model');

async function seedDemoUsers() {
  try {
    console.log('Connecting to MongoDB...');
    await connectDB();

    const defaultPassword = await bcrypt.hash('Password123!', 10);

    const demoUsers = [
      {
        email: 'organizer@carecamp.com',
        password: defaultPassword,
        name: 'Demo Organizer',
        photoURL: 'https://images.unsplash.com/photo-1559839734-2b71ea197ec2?w=150',
        role: 'organizer',
        phone: '+1 555-0199',
        address: 'CareCamp HQ, Medical Tower, NY',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'participant@carecamp.com',
        password: defaultPassword,
        name: 'Demo Participant',
        photoURL: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150',
        role: 'participant',
        phone: '+1 555-0144',
        address: '123 Health Ave, CA',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
    ];

    for (const user of demoUsers) {
      await User.findOneAndUpdate(
        { email: user.email },
        { $set: user },
        { upsert: true, new: true }
      );
      console.log(`Demo user upserted: ${user.email} (${user.role})`);
    }

    console.log('Demo users seed completed successfully.');
    await dbConnection.close();
    process.exit(0);
  } catch (error) {
    console.error('Seed demo users failed:', error);
    process.exit(1);
  }
}

seedDemoUsers();
