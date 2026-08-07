const express = require('express');
const router = express.Router();
const campsController = require('./camps.controller');
const campsSchema = require('./camps.schema');
const validate = require('../../middlewares/validate.middleware');
const {
  verifyFBToken,
  verifyOrganizer,
  verifyParticipant,
} = require('../../middlewares/auth.middleware');

router.get('/camps', campsController.getCamps);
router.get('/camps/:id', validate(campsSchema.idParamSchema), campsController.getCampById);
router.post(
  '/camps',
  verifyFBToken,
  verifyOrganizer,
  validate(campsSchema.createCampSchema),
  campsController.addCamp
);
router.patch(
  '/camps/:campId',
  verifyFBToken,
  verifyOrganizer,
  validate(campsSchema.updateCampSchema),
  campsController.updateCamp
);
router.patch(
  '/camps/:id/increment',
  verifyFBToken,
  validate(campsSchema.idParamSchema),
  campsController.incrementParticipantCount
);
router.delete(
  '/delete-camp/:campId',
  verifyFBToken,
  verifyOrganizer,
  validate(campsSchema.campIdParamSchema),
  campsController.deleteCamp
);
router.get('/organizer/camps', verifyFBToken, verifyOrganizer, campsController.getOrganizerCamps);
router.get(
  '/camps-with-registrations/:email',
  verifyFBToken,
  verifyParticipant,
  campsController.getCampsWithRegistrations
);

module.exports = router;
