const admin = require('../config/firebase');
const { getCollections } = require('../config/db');

const verifyFBToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
};

const verifyOrganizer = async (req, res, next) => {
  try {
    const { usersCollection } = getCollections();
    const user = await usersCollection.findOne({ email: req.user.email });
    if (user?.role !== 'organizer') {
      return res.status(403).json({ success: false, message: 'Organizer access required' });
    }
    next();
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to verify user role' });
  }
};

const verifyParticipant = async (req, res, next) => {
  try {
    const { usersCollection } = getCollections();
    const user = await usersCollection.findOne({ email: req.user.email });
    if (user?.role !== 'participant') {
      return res.status(403).json({ success: false, message: 'Participant access required' });
    }
    next();
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Failed to verify user role' });
  }
};

module.exports = {
  verifyFBToken,
  verifyOrganizer,
  verifyParticipant,
};
