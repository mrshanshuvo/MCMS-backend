const express = require('express');
const router = express.Router();
const publicController = require('./public.controller');
const { contactMessageSchema } = require('./public.schema');
const validate = require('../../middlewares/validate.middleware');

router.get('/successStories', publicController.getSuccessStories);
router.get('/faqs', publicController.getFaqs);
router.get('/blogs', publicController.getBlogs);
router.post('/contact', validate(contactMessageSchema), publicController.submitContactMessage);

module.exports = router;
