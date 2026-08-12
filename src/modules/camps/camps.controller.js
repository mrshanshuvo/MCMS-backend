const campsService = require('./camps.service');
const sendResponse = require('../../utils/response');

const getCamps = async (req, res) => {
  try {
    const result = await campsService.findAllCampsInDB(req.query);
    return sendResponse(res, 200, {
      success: true,
      data: result.camps,
      meta: result.meta,
    });
  } catch (error) {
    console.error('Error fetching camps:', error);
    return sendResponse(res, 500, { success: false, message: 'Server error' });
  }
};

const getCampById = async (req, res) => {
  try {
    const { id } = req.params;
    const camp = await campsService.findCampByIdInDB(id);
    if (!camp) {
      return sendResponse(res, 404, { success: false, message: 'Camp not found' });
    }
    return sendResponse(res, 200, { success: true, data: { camp } });
  } catch (error) {
    console.error('Error fetching camp by ID:', error);
    return sendResponse(res, 500, { success: false, message: 'Server error' });
  }
};

const addCamp = async (req, res) => {
  try {
    const result = await campsService.createCampInDB(req.body, req.user.email);
    return sendResponse(res, 201, {
      success: true,
      message: 'Camp added',
      data: { campId: result.insertedId },
    });
  } catch (error) {
    console.error('Error adding camp:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to add camp' });
  }
};

const getOrganizerCamps = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 5;
    const result = await campsService.findOrganizerCampsInDB(req.user.email, page, limit);
    return sendResponse(res, 200, {
      success: true,
      data: result.camps,
      meta: result.meta,
    });
  } catch (error) {
    console.error('Error fetching organizer camps:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch organizer camps' });
  }
};

const incrementParticipantCount = async (req, res) => {
  try {
    const { id } = req.params;
    const result = await campsService.incrementParticipantCountInDB(id);
    if (result.modifiedCount === 0) {
      return sendResponse(res, 404, {
        success: false,
        message: 'Camp not found or count not updated',
      });
    }
    return sendResponse(res, 200, { success: true });
  } catch (error) {
    console.error('Increment Error:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to increment count' });
  }
};

const updateCamp = async (req, res) => {
  try {
    const { campId } = req.params;
    const { name, location, fees, dateTime, healthcareProfessional, description, image, imageURL } =
      req.body;

    const updateFields = {};
    if (name !== undefined) updateFields.name = name;
    if (location !== undefined) updateFields.location = location;
    if (fees !== undefined) updateFields.fees = Number(fees);
    if (dateTime !== undefined) updateFields.dateTime = dateTime;
    if (healthcareProfessional !== undefined)
      updateFields.healthcareProfessional = healthcareProfessional;
    if (description !== undefined) updateFields.description = description;

    const finalImage = imageURL || image;
    if (finalImage !== undefined) {
      updateFields.image = finalImage;
      updateFields.imageURL = finalImage;
    }

    const result = await campsService.updateCampInDB(
      campId,
      req.user?.role === 'organizer' ? null : req.user?.email,
      updateFields
    );

    if (!result) {
      return sendResponse(res, 404, {
        success: false,
        message: 'Camp not found',
      });
    }

    return sendResponse(res, 200, {
      success: true,
      message: 'Camp updated successfully',
      data: result,
    });
  } catch (error) {
    console.error('Error updating camp:', error);
    return sendResponse(res, 500, { success: false, message: error.message });
  }
};

const deleteCamp = async (req, res) => {
  try {
    const { campId } = req.params;
    const result = await campsService.deleteCampInDB(campId, req.user.email);

    if (!result) {
      return sendResponse(res, 404, {
        success: false,
        message: 'Camp not found or not owned by organizer',
      });
    }

    if (result.deletedCount > 0) {
      return sendResponse(res, 200, {
        success: true,
        data: { deletedCount: result.deletedCount },
      });
    } else {
      return sendResponse(res, 404, { success: false, message: 'Camp not found' });
    }
  } catch (error) {
    console.error('Error deleting camp:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to delete camp' });
  }
};

const getCampsWithRegistrations = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 5;
    const result = await campsService.findCampsWithRegistrationsInDB(req.params.email, page, limit);
    return sendResponse(res, 200, {
      success: true,
      data: result.results,
      meta: result.meta,
    });
  } catch (error) {
    console.error('Error fetching camps:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to fetch camps data' });
  }
};

module.exports = {
  getCamps,
  getCampById,
  addCamp,
  getOrganizerCamps,
  incrementParticipantCount,
  updateCamp,
  deleteCamp,
  getCampsWithRegistrations,
};
