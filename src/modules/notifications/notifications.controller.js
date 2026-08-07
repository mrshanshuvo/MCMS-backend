const notificationsService = require('./notifications.service');
const sendResponse = require('../../utils/response');

const getUserNotifications = async (req, res) => {
  try {
    const result = await notificationsService.findUserNotificationsInDB(req.user.email, req.query);
    return sendResponse(res, 200, {
      success: true,
      data: result.notifications,
      meta: {
        ...result.pagination,
        unreadCount: result.unreadCount,
      },
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch notifications' });
  }
};

const markNotificationRead = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await notificationsService.markNotificationReadInDB(id, req.user.email);
    if (result.matchedCount === 0) {
      return sendResponse(res, 404, { success: false, message: 'Notification not found' });
    }
    return sendResponse(res, 200, { success: true, message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error updating notification:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to update notification' });
  }
};

const markAllRead = async (req, res) => {
  try {
    const result = await notificationsService.markAllNotificationsReadInDB(req.user.email);
    return sendResponse(res, 200, {
      success: true,
      message: `${result.modifiedCount} notifications marked as read`,
    });
  } catch (error) {
    console.error('Error updating notifications:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to update notifications' });
  }
};

module.exports = {
  getUserNotifications,
  markNotificationRead,
  markAllRead,
};
