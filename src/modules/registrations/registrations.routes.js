const express = require('express');
const router = express.Router();
const registrationsController = require('./registrations.controller');
const {
  verifyFBToken,
  verifyOrganizer,
  verifyParticipant,
} = require('../../middlewares/auth.middleware');

router.post(
  '/registrations',
  verifyFBToken,
  verifyParticipant,
  registrationsController.registerForCamp
);
router.get('/registrations/check', verifyFBToken, registrationsController.checkRegistration);
router.delete('/registrations/:id', verifyFBToken, registrationsController.deleteRegistration);
router.get(
  '/registrations',
  verifyFBToken,
  verifyOrganizer,
  registrationsController.getAllRegistrations
);
router.delete(
  '/cancel-registration/:campId',
  verifyFBToken,
  registrationsController.cancelRegistration
);
router.get(
  '/analytics/:participantId',
  verifyFBToken,
  registrationsController.getParticipantAnalytics
);

module.exports = router;
