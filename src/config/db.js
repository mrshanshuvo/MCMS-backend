const { MongoClient, ServerApiVersion } = require('mongodb');

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.ezlz7xu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;
let collections = {};

async function connectDB() {
  if (db) return { db, collections };

  await client.connect();
  db = client.db('medicalDB');

  collections = {
    usersCollection: db.collection('users'),
    campsCollection: db.collection('camps'),
    registrationsCollection: db.collection('registrations'),
    paymentsCollection: db.collection('payments'),
    feedbackCollection: db.collection('feedback'),
    successStoriesCollection: db.collection('success_stories'),
    blogCollection: db.collection('blogs'),
    faqCollection: db.collection('faq'),
    notificationsCollection: db.collection('notifications'),
  };

  // Create Indexes
  await collections.registrationsCollection.createIndex({ participantEmail: 1 });
  await collections.registrationsCollection.createIndex({ campId: 1 });
  await collections.registrationsCollection.createIndex(
    { transactionId: 1 },
    { unique: true, sparse: true }
  );
  await collections.feedbackCollection.createIndex({ campId: 1 });
  await collections.feedbackCollection.createIndex({ participantEmail: 1 });
  await collections.notificationsCollection.createIndex({ userEmail: 1, read: 1 });

  console.log('Successfully connected to MongoDB');
  return { db, collections };
}

function getCollections() {
  if (!db) {
    throw new Error('Database not initialized. Call connectDB first.');
  }
  return collections;
}

module.exports = {
  connectDB,
  getCollections,
  client,
};
