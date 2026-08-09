const jwt = require('jsonwebtoken');
const admin = require('../config/firebase');
const User = require('../modules/users/users.model');
const sendResponse = require('../utils/response');
const { env } = require('../config/env');

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendResponse(res, 401, { success: false, message: 'Unauthorized: No token provided' });
  }

  const token = authHeader.split(' ')[1];

  // Try native JWT verification first
  try {
    const decoded = jwt.verify(
      token,
      env.JWT_SECRET || process.env.JWT_SECRET || 'supersecretjwtkey12345'
    );
    req.user = decoded;
    return next();
  } catch {
    // Native JWT verification failed, attempt Firebase ID token fallback
  }

  try {
    const decodedFB = await admin.auth().verifyIdToken(token);
    req.user = decodedFB;
    return next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    return sendResponse(res, 401, { success: false, message: 'Unauthorized: Invalid token' });
  }
};

const verifyOrganizer = async (req, res, next) => {
  try {
    if (req.user?.role === 'organizer') {
      return next();
    }

    const user = await User.findOne({ email: req.user?.email });
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
    if (req.user?.role === 'participant') {
      return next();
    }

    const user = await User.findOne({ email: req.user?.email });
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
  verifyToken,
  verifyFBToken: verifyToken, // Alias for backwards compatibility
  verifyOrganizer,
  verifyParticipant,
};
