const express = require('express');
const router = express.Router();
const campsController = require('./camps.controller');
const campsSchema = require('./camps.schema');
const validate = require('../../middlewares/validate.middleware');
const {
  verifyToken,
  verifyOrganizer,
  verifyParticipant,
} = require('../../middlewares/auth.middleware');

// Public listing & single item routes
router.get('/camps', campsController.getCamps);
router.get('/items', campsController.getCamps);
router.get('/camps/:id', validate(campsSchema.idParamSchema), campsController.getCampById);
router.get('/items/:id', validate(campsSchema.idParamSchema), campsController.getCampById);

// Admin/Organizer mutation routes (POST, PUT, PATCH, DELETE)
router.post(
  '/camps',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.createCampSchema),
  campsController.addCamp
);
router.post(
  '/items',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.createCampSchema),
  campsController.addCamp
);

router.put(
  '/camps/:campId',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.updateCampSchema),
  campsController.updateCamp
);
router.put(
  '/items/:campId',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.updateCampSchema),
  campsController.updateCamp
);
router.patch(
  '/camps/:campId',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.updateCampSchema),
  campsController.updateCamp
);

router.delete(
  '/camps/:campId',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.campIdParamSchema),
  campsController.deleteCamp
);
router.delete(
  '/items/:campId',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.campIdParamSchema),
  campsController.deleteCamp
);
router.delete(
  '/delete-camp/:campId',
  verifyToken,
  verifyOrganizer,
  validate(campsSchema.campIdParamSchema),
  campsController.deleteCamp
);

// Participant & organizer specialized routes
router.patch(
  '/camps/:id/increment',
  verifyToken,
  validate(campsSchema.idParamSchema),
  campsController.incrementParticipantCount
);
router.get('/organizer/camps', verifyToken, verifyOrganizer, campsController.getOrganizerCamps);
router.get(
  '/camps-with-registrations/:email',
  verifyToken,
  verifyParticipant,
  campsController.getCampsWithRegistrations
);

module.exports = router;
