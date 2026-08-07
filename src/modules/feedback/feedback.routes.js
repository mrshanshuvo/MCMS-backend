const express = require('express');
const router = express.Router();
const feedbackController = require('./feedback.controller');
const { verifyFBToken } = require('../../middlewares/auth.middleware');

router.post('/feedback', verifyFBToken, feedbackController.submitFeedback);
router.get('/feedback', feedbackController.getFeedback);

module.exports = router;
