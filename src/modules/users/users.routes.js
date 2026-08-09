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
  '/:id/role',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.updateRoleSchema),
  usersController.updateUserRole
);
router.delete(
  '/:id',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.userParamSchema),
  usersController.deleteUser
);

// Email parameter aliases
router.patch(
  '/email/:email/role',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.updateRoleSchema),
  usersController.updateUserRole
);
router.delete(
  '/email/:email',
  verifyToken,
  verifyOrganizer,
  validate(usersSchema.userParamSchema),
  usersController.deleteUser
);

// Profile sync and legacy routes
router.post('/', verifyToken, validate(usersSchema.upsertUserSchema), usersController.upsertUser);
router.patch('/:email', verifyToken, usersController.updateLastLogin);
router.get(
  '/:email',
  verifyToken,
  validate(usersSchema.userParamSchema),
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
  validate(usersSchema.userParamSchema),
  usersController.getUserRole
);

module.exports = router;
