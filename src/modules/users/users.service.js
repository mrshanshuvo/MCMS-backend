const mongoose = require('mongoose');
const User = require('./users.model');

const escapeRegex = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const buildUserQuery = (identifier) => {
  if (!identifier) return {};
  if (mongoose.Types.ObjectId.isValid(identifier)) {
    return { $or: [{ _id: identifier }, { email: identifier }] };
  }
  return { email: identifier };
};

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
  return await User.findOne(buildUserQuery(email));
};

const updateUserInDB = async (email, updateFields) => {
  return await User.findOneAndUpdate(buildUserQuery(email), { $set: updateFields }, { new: true });
};

const findAllUsersInDB = async ({ page = '1', limit = '10', search = '', role = '' }) => {
  const pageNum = parseInt(page, 10) || 1;
  const limitNum = parseInt(limit, 10) || 10;
  const skip = (pageNum - 1) * limitNum;

  const query = {};
  if (role && role !== 'all') {
    query.role = role;
  }
  if (search) {
    const searchRegex = new RegExp(escapeRegex(search), 'i');
    query.$or = [{ name: searchRegex }, { email: searchRegex }];
  }

  const [total, users] = await Promise.all([
    User.countDocuments(query),
    User.find(query).sort({ created_at: -1 }).skip(skip).limit(limitNum).lean(),
  ]);

  return {
    users,
    pagination: {
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    },
  };
};

const updateUserRoleInDB = async (idOrEmail, role) => {
  return await User.findOneAndUpdate(buildUserQuery(idOrEmail), { $set: { role } }, { new: true });
};

const deleteUserInDB = async (idOrEmail) => {
  return await User.findOneAndDelete(buildUserQuery(idOrEmail));
};

module.exports = {
  upsertUserInDB,
  updateLastLoginInDB,
  findUserByEmailInDB,
  updateUserInDB,
  findAllUsersInDB,
  updateUserRoleInDB,
  deleteUserInDB,
};
