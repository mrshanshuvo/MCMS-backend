const admin = require('../config/firebase');
const User = require('../modules/users/users.model');
const sendResponse = require('../utils/response');

const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return sendResponse(res, 401, { success: false, message: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    return sendResponse(res, 401, { success: false, message: 'Unauthorized' });
  }
};

const verifyOrganizer = async (req, res, next) => {
  try {
    // Fast path: Check custom claims on token first
    if (req.user.role === 'organizer') {
      return next();
    }

    const user = await User.findOne({ email: req.user.email });
    if (user?.role !== 'organizer') {
      return sendResponse(res, 403, { success: false, message: 'Organizer access required' });
    }

    req.user.role = 'organizer';
    next();
  } catch {
    return sendResponse(res, 500, { success: false, message: 'Failed to verify user role' });
  }
};

const verifyParticipant = async (req, res, next) => {
  try {
    // Fast path: Check custom claims on token first
    if (req.user.role === 'participant') {
      return next();
    }

    const user = await User.findOne({ email: req.user.email });
    if (user?.role !== 'participant') {
      return sendResponse(res, 403, { success: false, message: 'Participant access required' });
    }

    req.user.role = 'participant';
    next();
  } catch {
    return sendResponse(res, 500, { success: false, message: 'Failed to verify user role' });
  }
};

module.exports = {
  verifyFBToken,
  verifyOrganizer,
  verifyParticipant,
};
