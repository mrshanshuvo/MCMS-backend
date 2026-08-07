const analyticsService = require('./analytics.service');
const sendResponse = require('../../utils/response');

const getOrganizerOverview = async (req, res) => {
  try {
    const overview = await analyticsService.getOrganizerOverviewInDB(req.user.email);
    return sendResponse(res, 200, { success: true, data: overview });
  } catch (error) {
    console.error('Error fetching analytics overview:', error);
    return sendResponse(res, 500, {
      success: false,
      message: 'Failed to fetch analytics overview',
    });
  }
};

const exportRegistrationsCSV = async (req, res) => {
  try {
    const { campId } = req.query;
    const csvData = await analyticsService.exportRegistrationsCSVInDB(req.user.email, campId);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="registrations.csv"');
    return res.status(200).send(csvData);
  } catch (error) {
    console.error('Error exporting registrations CSV:', error);
    return sendResponse(res, 500, {
      success: false,
      message: 'Failed to export registrations CSV',
    });
  }
};

const exportPaymentsCSV = async (req, res) => {
  try {
    const csvData = await analyticsService.exportPaymentsCSVInDB(req.user.email);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="payments.csv"');
    return res.status(200).send(csvData);
  } catch (error) {
    console.error('Error exporting payments CSV:', error);
    return sendResponse(res, 500, { success: false, message: 'Failed to export payments CSV' });
  }
};

module.exports = {
  getOrganizerOverview,
  exportRegistrationsCSV,
  exportPaymentsCSV,
};
