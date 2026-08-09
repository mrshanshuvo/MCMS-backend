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
  const identifier = req.params.id || req.params.email;
  const { last_login } = req.body;

  if (
    req.user.email !== identifier &&
    req.user.id !== identifier &&
    req.user.role !== 'organizer'
  ) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  try {
    const result = await usersService.updateLastLoginInDB(identifier, last_login);
    if (!result) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, { success: true, message: 'Last login updated', data: result });
  } catch (error) {
    console.error('Error updating last_login:', error);
    return sendResponse(res, 500, { success: false, message: 'Internal server error' });
  }
};

const getUserByEmail = async (req, res) => {
  const identifier = req.params.id || req.params.email || req.user.email;

  if (
    req.user.email !== identifier &&
    req.user.id !== identifier &&
    req.user.role !== 'organizer'
  ) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  try {
    const user = await usersService.findUserByEmailInDB(identifier);
    if (user) {
      return sendResponse(res, 200, { success: true, data: user });
    }
    return sendResponse(res, 404, { success: false, message: 'User not found' });
  } catch (error) {
    console.error('Error fetching user:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch user' });
  }
};

const getMyProfile = async (req, res) => {
  try {
    const user = await usersService.findUserByEmailInDB(req.user.email);
    if (user) {
      return sendResponse(res, 200, { success: true, data: user });
    }
    return sendResponse(res, 404, { success: false, message: 'User profile not found' });
  } catch (error) {
    console.error('Error fetching my profile:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch profile' });
  }
};

const updateUser = async (req, res) => {
  const identifier = req.params.id || req.params.email || req.user.email;

  if (
    req.user.email !== identifier &&
    req.user.id !== identifier &&
    req.user.role !== 'organizer'
  ) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  const { name, photoURL, phone, address } = req.body;
  const updateFields = {};
  if (name !== undefined) updateFields.name = name;
  if (photoURL !== undefined) updateFields.photoURL = photoURL;
  if (phone !== undefined) updateFields.phone = phone;
  if (address !== undefined) updateFields.address = address;

  try {
    const updatedUser = await usersService.updateUserInDB(identifier, updateFields);
    if (!updatedUser) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, { success: true, data: updatedUser });
  } catch (error) {
    console.error('Error updating user:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to update user' });
  }
};

const updateMyProfile = async (req, res) => {
  const { name, photoURL, phone, address } = req.body;
  const updateFields = {};
  if (name !== undefined) updateFields.name = name;
  if (photoURL !== undefined) updateFields.photoURL = photoURL;
  if (phone !== undefined) updateFields.phone = phone;
  if (address !== undefined) updateFields.address = address;

  try {
    const updatedUser = await usersService.updateUserInDB(req.user.email, updateFields);
    if (!updatedUser) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, { success: true, data: updatedUser });
  } catch (error) {
    console.error('Error updating profile:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to update profile' });
  }
};

const getUserRole = async (req, res) => {
  const identifier = req.params.id || req.params.email || req.user.email;

  if (
    req.user.email !== identifier &&
    req.user.id !== identifier &&
    req.user.role !== 'organizer'
  ) {
    return sendResponse(res, 403, { success: false, message: 'Forbidden' });
  }

  try {
    const user = await usersService.findUserByEmailInDB(identifier);
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

const getAllUsers = async (req, res, next) => {
  try {
    const result = await usersService.findAllUsersInDB(req.query);
    return sendResponse(res, 200, {
      success: true,
      data: result.users,
      pagination: result.pagination,
    });
  } catch (error) {
    next(error);
  }
};

const updateUserRole = async (req, res, next) => {
  const identifier = req.params.id || req.params.email;
  const { role } = req.body;

  try {
    const updatedUser = await usersService.updateUserRoleInDB(identifier, role);
    if (!updatedUser) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, {
      success: true,
      message: `User role updated to ${role}`,
      data: updatedUser,
    });
  } catch (error) {
    next(error);
  }
};

const deleteUser = async (req, res, next) => {
  const identifier = req.params.id || req.params.email;

  try {
    const deletedUser = await usersService.deleteUserInDB(identifier);
    if (!deletedUser) {
      return sendResponse(res, 404, { success: false, message: 'User not found' });
    }
    return sendResponse(res, 200, {
      success: true,
      message: 'User deleted successfully',
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  upsertUser,
  updateLastLogin,
  getUserByEmail,
  getMyProfile,
  updateUser,
  updateMyProfile,
  getUserRole,
  getAllUsers,
  updateUserRole,
  deleteUser,
};
