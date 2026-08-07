const usersService = require('./users.service');
const sendResponse = require('../../utils/response');

const upsertUser = async (req, res) => {
  try {
    const result = await usersService.upsertUserInDB(req.body);
    return sendResponse(res, 200, { success: true, data: result });
  } catch (error) {
    console.error('Error upserting user:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to upsert user.' });
  }
};

const updateLastLogin = async (req, res) => {
  const { email } = req.params;
  const { last_login } = req.body;

  if (req.user.email !== email) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  try {
    const result = await usersService.updateLastLoginInDB(email, last_login);
    if (result.matchedCount === 0) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, { success: true, message: 'Last login updated', data: result });
  } catch (error) {
    console.error('Error updating last_login:', error);
    return sendResponse(res, 500, { success: false, message: 'Internal server error' });
  }
};

const getUserByEmail = async (req, res) => {
  const { email } = req.params;

  if (req.user.email !== email) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  try {
    const user = await usersService.findUserByEmailInDB(email);
    if (user) {
      return sendResponse(res, 200, { success: true, data: user });
    }
    return sendResponse(res, 404, { success: false, message: 'User not found' });
  } catch (error) {
    console.error('Error fetching user:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch user' });
  }
};

const updateUser = async (req, res) => {
  const { email } = req.params;

  if (req.user.email !== email) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  const { name, photoURL, phone, address } = req.body;
  const updateFields = {};
  if (name !== undefined) updateFields.name = name;
  if (photoURL !== undefined) updateFields.photoURL = photoURL;
  if (phone !== undefined) updateFields.phone = phone;
  if (address !== undefined) updateFields.address = address;

  try {
    const updatedUser = await usersService.updateUserInDB(email, updateFields);
    if (!updatedUser) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, { success: true, data: updatedUser });
  } catch (error) {
    console.error('Error updating user:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to update user' });
  }
};

const getUserRole = async (req, res) => {
  const { email } = req.params;

  if (req.user.email !== email) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  try {
    const user = await usersService.findUserByEmailInDB(email);
    if (!user) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, {
      success: true,
      data: { role: user.role || 'participant' },
    });
  } catch (error) {
    console.error('Error fetching user role:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch user role' });
  }
};

module.exports = {
  upsertUser,
  updateLastLogin,
  getUserByEmail,
  updateUser,
  getUserRole,
};
