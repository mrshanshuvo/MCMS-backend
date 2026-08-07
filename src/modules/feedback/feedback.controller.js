const feedbackService = require('./feedback.service');
const sendResponse = require('../../utils/response');

const submitFeedback = async (req, res) => {
  try {
    const result = await feedbackService.submitFeedbackInDB(req.body, req.user.email);
    if (result.notAttended) {
      return sendResponse(res, 403, {
        success: false,
        message: 'You must attend the camp to provide feedback',
      });
    }
    if (result.duplicate) {
      return sendResponse(res, 400, { success: false, message: 'Feedback already submitted' });
    }
    return sendResponse(res, 201, { success: true });
  } catch (error) {
    console.error('Feedback error:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to submit feedback' });
  }
};

const getFeedback = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 5;
    const feedback = await feedbackService.findFeedbackInDB(limit);
    return sendResponse(res, 200, { success: true, data: feedback });
  } catch (error) {
    console.error('Feedback fetch error:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch feedback' });
  }
};

module.exports = {
  submitFeedback,
  getFeedback,
};
