const express = require('express');
const router = express.Router();
const usersController = require('./users.controller');
const usersSchema = require('./users.schema');
const validate = require('../../middlewares/validate.middleware');
const { verifyFBToken } = require('../../middlewares/auth.middleware');

router.post('/', verifyFBToken, validate(usersSchema.upsertUserSchema), usersController.upsertUser);
router.patch('/:email', verifyFBToken, usersController.updateLastLogin);
router.get(
  '/:email',
  verifyFBToken,
  validate(usersSchema.emailParamSchema),
  usersController.getUserByEmail
);
router.put(
  '/:email',
  verifyFBToken,
  validate(usersSchema.updateUserSchema),
  usersController.updateUser
);
router.get(
  '/:email/role',
  verifyFBToken,
  validate(usersSchema.emailParamSchema),
  usersController.getUserRole
);

module.exports = router;
