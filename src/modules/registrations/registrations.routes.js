const express = require('express');
const router = express.Router();
const registrationsController = require('./registrations.controller');
const registrationsSchema = require('./registrations.schema');
const validate = require('../../middlewares/validate.middleware');
const {
  verifyFBToken,
  verifyOrganizer,
  verifyParticipant,
} = require('../../middlewares/auth.middleware');

router.post(
  '/registrations',
  verifyFBToken,
  verifyParticipant,
  validate(registrationsSchema.registerCampSchema),
  registrationsController.registerForCamp
);
router.get(
  '/registrations/check',
  verifyFBToken,
  validate(registrationsSchema.checkRegistrationSchema),
  registrationsController.checkRegistration
);
router.delete(
  '/registrations/:id',
  verifyFBToken,
  validate(registrationsSchema.idParamSchema),
  registrationsController.deleteRegistration
);
router.get(
  '/registrations',
  verifyFBToken,
  verifyOrganizer,
  registrationsController.getAllRegistrations
);
router.delete(
  '/cancel-registration/:campId',
  verifyFBToken,
  validate(registrationsSchema.campIdParamSchema),
  registrationsController.cancelRegistration
);
router.get(
  '/analytics/:participantId',
  verifyFBToken,
  registrationsController.getParticipantAnalytics
);

module.exports = router;
