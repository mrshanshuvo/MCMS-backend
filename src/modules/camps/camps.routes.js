const express = require('express');
const router = express.Router();
const campsController = require('./camps.controller');
const {
  verifyFBToken,
  verifyOrganizer,
  verifyParticipant,
} = require('../../middlewares/auth.middleware');

router.get('/camps', campsController.getCamps);
router.get('/camps/:id', campsController.getCampById);
router.post('/camps', verifyFBToken, verifyOrganizer, campsController.addCamp);
router.patch('/camps/:campId', verifyFBToken, verifyOrganizer, campsController.updateCamp);
router.patch('/camps/:id/increment', verifyFBToken, campsController.incrementParticipantCount);
router.delete('/delete-camp/:campId', verifyFBToken, verifyOrganizer, campsController.deleteCamp);
router.get('/organizer/camps', verifyFBToken, verifyOrganizer, campsController.getOrganizerCamps);
router.get(
  '/camps-with-registrations/:email',
  verifyFBToken,
  verifyParticipant,
  campsController.getCampsWithRegistrations
);

module.exports = router;
