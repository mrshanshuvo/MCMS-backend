const express = require('express');
const router = express.Router();
const publicController = require('./public.controller');

router.get('/successStories', publicController.getSuccessStories);
router.get('/faqs', publicController.getFaqs);
router.get('/blogs', publicController.getBlogs);

module.exports = router;
