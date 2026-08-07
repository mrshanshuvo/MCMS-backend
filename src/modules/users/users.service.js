const { getCollections } = require('../../config/db');

const upsertUserInDB = async (userData) => {
  const { email, name, photoURL, created_at, last_login } = userData;
  const updateDoc = {
    $setOnInsert: {
      name,
      photoURL,
      role: 'participant',
      created_at,
    },
    $set: {
      last_login,
    },
  };
  const { usersCollection } = getCollections();
  return await usersCollection.updateOne({ email }, updateDoc, { upsert: true });
};

const updateLastLoginInDB = async (email, last_login) => {
  const { usersCollection } = getCollections();
  return await usersCollection.updateOne({ email }, { $set: { last_login } });
};

const findUserByEmailInDB = async (email) => {
  const { usersCollection } = getCollections();
  return await usersCollection.findOne({ email });
};

const updateUserInDB = async (email, updateFields) => {
  const { usersCollection } = getCollections();
  const updateDoc = { $set: updateFields };
  const result = await usersCollection.updateOne({ email }, updateDoc);
  if (result.matchedCount === 0) return null;
  return await usersCollection.findOne({ email });
};

module.exports = {
  upsertUserInDB,
  updateLastLoginInDB,
  findUserByEmailInDB,
  updateUserInDB,
};
