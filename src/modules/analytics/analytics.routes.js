const express = require('express');
const router = express.Router();
const analyticsController = require('./analytics.controller');
const analyticsSchema = require('./analytics.schema');
const validate = require('../../middlewares/validate.middleware');
const { verifyFBToken, verifyOrganizer } = require('../../middlewares/auth.middleware');

router.get(
  '/organizer/overview',
  verifyFBToken,
  verifyOrganizer,
  analyticsController.getOrganizerOverview
);
router.get('/overview', verifyFBToken, verifyOrganizer, analyticsController.getOrganizerOverview);
router.get('/charts', verifyFBToken, verifyOrganizer, analyticsController.getOrganizerOverview);
router.get(
  '/export/registrations',
  verifyFBToken,
  verifyOrganizer,
  validate(analyticsSchema.exportQuerySchema),
  analyticsController.exportRegistrationsCSV
);
router.get(
  '/export/payments',
  verifyFBToken,
  verifyOrganizer,
  analyticsController.exportPaymentsCSV
);

module.exports = router;
