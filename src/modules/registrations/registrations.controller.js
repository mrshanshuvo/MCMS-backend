const registrationsService = require('./registrations.service');
const sendResponse = require('../../utils/response');

const registerForCamp = async (req, res) => {
  try {
    const result = await registrationsService.registerForCampInDB(req.body);
    if (result.duplicate) {
      return sendResponse(res, 400, {
        success: false,
        message: 'Already registered for this camp',
      });
    }
    return sendResponse(res, 201, {
      success: true,
      data: { registrationId: result.registrationId },
    });
  } catch (error) {
    console.error('Registration Error:', error);
    if (error.code === 11000) {
      return sendResponse(res, 400, { success: false, message: 'Duplicate registration detected' });
    }
    return sendResponse(res, 500, { success: false, message: 'Registration failed' });
  }
};

const checkRegistration = async (req, res) => {
  try {
    const { campId } = req.query;
    const isRegistered = await registrationsService.checkRegistrationInDB(campId, req.user.email);
    return sendResponse(res, 200, { success: true, data: { registered: isRegistered } });
  } catch (error) {
    console.error('Error checking registration:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to check registration' });
  }
};

const deleteRegistration = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await registrationsService.deleteRegistrationInDB(id, req.user.email);

    if (!result) {
      return sendResponse(res, 404, { success: false, message: 'Registration not found' });
    }
    if (result.forbidden) {
      return sendResponse(res, 403, { success: false, message: 'Forbidden' });
    }
    return sendResponse(res, 200, { success: true, message: 'Registration deleted successfully' });
  } catch (error) {
    console.error('Error deleting registration:', error);
    return sendResponse(res, 500, { success: false, message: 'Server error' });
  }
};

const getAllRegistrations = async (req, res) => {
  try {
    const result = await registrationsService.findAllRegistrationsInDB(req.query);
    return sendResponse(res, 200, { success: true, data: result.data, meta: result.pagination });
  } catch (error) {
    console.error('Failed to get registrations:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch registrations' });
  }
};

const cancelRegistration = async (req, res) => {
  try {
    const { campId } = req.params;
    const result = await registrationsService.cancelRegistrationInDB(campId, req.user.email);

    if (!result) {
      return sendResponse(res, 404, { success: false, message: 'Registration not found' });
    }
    if (result.cannotCancel) {
      return sendResponse(res, 400, {
        success: false,
        message: 'Cannot cancel after payment. Please contact support.',
      });
    }
    return sendResponse(res, 200, { success: true });
  } catch (error) {
    console.error('Error cancelling registration:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to cancel registration' });
  }
};

const getParticipantAnalytics = async (req, res) => {
  try {
    const analytics = await registrationsService.getParticipantAnalyticsInDB(req.user.email);
    return sendResponse(res, 200, { success: true, data: analytics });
  } catch (error) {
    console.error('Analytics error:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch analytics' });
  }
};

module.exports = {
  registerForCamp,
  checkRegistration,
  deleteRegistration,
  getAllRegistrations,
  cancelRegistration,
  getParticipantAnalytics,
};
