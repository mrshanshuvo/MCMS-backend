const Notification = require('./notifications.model');

const createNotification = async ({ userEmail, title, message, type, link }) => {
  return await Notification.create({
    userEmail,
    title,
    message,
    type,
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

  const [total, unreadCount, notifications] = await Promise.all([
    Notification.countDocuments(query),
    Notification.countDocuments({ userEmail, read: false }),
    Notification.find(query).sort({ createdAt: -1 }).skip(skip).limit(limitNum).lean(),
  ]);

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
  return await Notification.findOneAndUpdate(
    { _id: notificationId, userEmail },
    { $set: { read: true } },
    { new: true }
  );
};

const markAllNotificationsReadInDB = async (userEmail) => {
  return await Notification.updateMany({ userEmail, read: false }, { $set: { read: true } });
};

module.exports = {
  createNotification,
  findUserNotificationsInDB,
  markNotificationReadInDB,
  markAllNotificationsReadInDB,
};
