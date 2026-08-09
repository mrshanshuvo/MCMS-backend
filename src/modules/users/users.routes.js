const express = require('express');
const router = express.Router();
const usersController = require('./users.controller');
const usersSchema = require('./users.schema');
const validate = require('../../middlewares/validate.middleware');
const { verifyToken, verifyOrganizer } = require('../../middlewares/auth.middleware');

// Current user profile routes
router.get('/profile', verifyToken, usersController.getMyProfile);
router.put(
  '/profile',
  verifyToken,
  validate(usersSchema.updateUserSchema),
  usersController.updateMyProfile
);

// Admin User Management Routes
router.get(
  '/',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.getAllUsersSchema),
  usersController.getAllUsers
);
router.patch(
  '/:email/role',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.updateRoleSchema),
  usersController.updateUserRole
);
router.delete(
  '/:email',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.emailParamSchema),
  usersController.deleteUser
);

// Profile sync and legacy routes
router.post('/', verifyToken, validate(usersSchema.upsertUserSchema), usersController.upsertUser);
router.patch('/:email', verifyToken, usersController.updateLastLogin);
router.get(
  '/:email',
  verifyToken,
  validate(usersSchema.emailParamSchema),
  usersController.getUserByEmail
);
router.put(
  '/:email',
  verifyToken,
  validate(usersSchema.updateUserSchema),
  usersController.updateUser
);
router.get(
  '/:email/role',
  verifyToken,
  validate(usersSchema.emailParamSchema),
  usersController.getUserRole
);

module.exports = router;
