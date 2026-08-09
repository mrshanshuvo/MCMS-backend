const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../users/users.model');
const { env } = require('../../config/env');

const generateToken = (user) => {
  const secret = env.JWT_SECRET || process.env.JWT_SECRET || 'supersecretjwtkey12345';
  const expiresIn = env.JWT_EXPIRES_IN || process.env.JWT_EXPIRES_IN || '7d';

  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role || 'participant',
      name: user.name,
    },
    secret,
    { expiresIn }
  );
};

const registerUserInDB = async ({ email, password, name, photoURL, role }) => {
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return { duplicate: true };
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newUser = await User.create({
    email,
    password: hashedPassword,
    name: name || 'Anonymous User',
    photoURL: photoURL || '',
    role: role || 'participant',
    created_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
  });

  const token = generateToken(newUser);

  const userObject = newUser.toObject();
  delete userObject.password;

  return {
    success: true,
    token,
    user: userObject,
  };
};

const loginUserInDB = async ({ email, password }) => {
  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    return { invalidCredentials: true };
  }

  if (!user.password) {
    return { socialUser: true };
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return { invalidCredentials: true };
  }

  const lastLogin = new Date().toISOString();
  await User.findByIdAndUpdate(user._id, { $set: { last_login: lastLogin } });

  const token = generateToken(user);
  const userObject = user.toObject();
  delete userObject.password;
  userObject.last_login = lastLogin;

  return {
    success: true,
    token,
    user: userObject,
  };
};

module.exports = {
  generateToken,
  registerUserInDB,
  loginUserInDB,
};
