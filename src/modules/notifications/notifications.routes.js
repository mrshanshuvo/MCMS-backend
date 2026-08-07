const express = require('express');
const router = express.Router();
const notificationsController = require('./notifications.controller');
const notificationsSchema = require('./notifications.schema');
const validate = require('../../middlewares/validate.middleware');
const { verifyFBToken } = require('../../middlewares/auth.middleware');

router.get(
  '/',
  verifyFBToken,
  validate(notificationsSchema.getNotificationsSchema),
  notificationsController.getUserNotifications
);
router.patch('/read-all', verifyFBToken, notificationsController.markAllRead);
router.patch(
  '/:id/read',
  verifyFBToken,
  validate(notificationsSchema.markReadSchema),
  notificationsController.markNotificationRead
);

module.exports = router;
