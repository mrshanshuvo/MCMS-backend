const express = require('express');
const router = express.Router();
const authController = require('./auth.controller');
const authSchema = require('./auth.schema');
const validate = require('../../middlewares/validate.middleware');

router.post('/register', validate(authSchema.registerSchema), authController.register);
router.post('/login', validate(authSchema.loginSchema), authController.login);

module.exports = router;
