const express = require('express');
const router = express.Router();
const feedbackController = require('./feedback.controller');
const feedbackSchema = require('./feedback.schema');
const validate = require('../../middlewares/validate.middleware');
const { verifyFBToken } = require('../../middlewares/auth.middleware');

router.post(
  '/feedback',
  verifyFBToken,
  validate(feedbackSchema.submitFeedbackSchema),
  feedbackController.submitFeedback
);
router.get('/feedback', feedbackController.getFeedback);

module.exports = router;
