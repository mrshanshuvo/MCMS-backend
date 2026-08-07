const express = require('express');
const router = express.Router();
const usersController = require('./users.controller');
const { verifyFBToken } = require('../../middlewares/auth.middleware');

router.post('/', verifyFBToken, usersController.upsertUser);
router.patch('/:email', verifyFBToken, usersController.updateLastLogin);
router.get('/:email', usersController.getUserByEmail);
router.put('/:email', verifyFBToken, usersController.updateUser);
router.get('/:email/role', usersController.getUserRole);

module.exports = router;
