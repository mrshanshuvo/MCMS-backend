const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

const createNotification = async ({ userEmail, title, message, type, link }) => {
  const { notificationsCollection } = getCollections();
  return await notificationsCollection.insertOne({
    userEmail,
    title,
    message,
    type, // 'registration', 'payment', 'system'
    link: link || '',
    read: false,
    createdAt: new Date(),
  });
};

const findUserNotificationsInDB = async (
  userEmail,
  { page = 1, limit = 10, unreadOnly = false }
) => {
  const pageNum = parseInt(page, 10) || 1;
  const limitNum = parseInt(limit, 10) || 10;
  const skip = (pageNum - 1) * limitNum;

  const query = { userEmail };
  if (unreadOnly === 'true' || unreadOnly === true) {
    query.read = false;
  }

  const { notificationsCollection } = getCollections();
  const total = await notificationsCollection.countDocuments(query);
  const unreadCount = await notificationsCollection.countDocuments({ userEmail, read: false });

  const notifications = await notificationsCollection
    .find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limitNum)
    .toArray();

  return {
    notifications,
    unreadCount,
    pagination: {
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    },
  };
};

const markNotificationReadInDB = async (notificationId, userEmail) => {
  const { notificationsCollection } = getCollections();
  return await notificationsCollection.updateOne(
    { _id: new ObjectId(notificationId), userEmail },
    { $set: { read: true } }
  );
};

const markAllNotificationsReadInDB = async (userEmail) => {
  const { notificationsCollection } = getCollections();
  return await notificationsCollection.updateMany(
    { userEmail, read: false },
    { $set: { read: true } }
  );
};

module.exports = {
  createNotification,
  findUserNotificationsInDB,
  markNotificationReadInDB,
  markAllNotificationsReadInDB,
};
