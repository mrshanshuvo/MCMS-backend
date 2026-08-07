const publicService = require('./public.service');
const sendResponse = require('../../utils/response');

const getSuccessStories = async (req, res) => {
  try {
    const successStories = await publicService.findSuccessStoriesInDB();
    return sendResponse(res, 200, { success: true, data: successStories });
  } catch (error) {
    console.error('Error fetching success stories:', error);
    return sendResponse(res, 500, {
      success: false,
      message: 'Failed to fetch success stories',
    });
  }
};

const getFaqs = async (req, res) => {
  try {
    const faq = await publicService.findFaqsInDB();
    return sendResponse(res, 200, { success: true, data: faq });
  } catch (error) {
    console.error('Error fetching faq:', error);
    return sendResponse(res, 500, {
      success: false,
      message: 'Failed to fetch faq',
    });
  }
};

const getBlogs = async (req, res) => {
  try {
    const blog = await publicService.findBlogsInDB();
    return sendResponse(res, 200, { success: true, data: blog });
  } catch (error) {
    console.error('Error fetching blog:', error);
    return sendResponse(res, 500, {
      success: false,
      message: 'Failed to fetch blog',
    });
  }
};

module.exports = {
  getSuccessStories,
  getFaqs,
  getBlogs,
};
