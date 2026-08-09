const User = require('./users.model');

const upsertUserInDB = async (userData) => {
  const { email, name, photoURL, created_at, last_login } = userData;

  return await User.findOneAndUpdate(
    { email },
    {
      $setOnInsert: { name, photoURL, role: 'participant', created_at },
      $set: { last_login },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
};

const updateLastLoginInDB = async (email, last_login) => {
  return await User.findOneAndUpdate({ email }, { $set: { last_login } });
};

const findUserByEmailInDB = async (email) => {
  return await User.findOne({ email });
};

const updateUserInDB = async (email, updateFields) => {
  return await User.findOneAndUpdate({ email }, { $set: updateFields }, { new: true });
};

module.exports = {
  upsertUserInDB,
  updateLastLoginInDB,
  findUserByEmailInDB,
  updateUserInDB,
};
