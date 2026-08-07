const { getCollections } = require('../../config/db');

const getSuccessStories = async (req, res) => {
  try {
    const { successStoriesCollection } = getCollections();
    const successStories = await successStoriesCollection.find().toArray();
    res.send({ success: true, data: successStories });
  } catch (error) {
    console.error('Error fetching success stories:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to fetch success stories',
    });
  }
};

const getFaqs = async (req, res) => {
  try {
    const { faqCollection } = getCollections();
    const faq = await faqCollection.find().toArray();
    res.send({ success: true, data: faq });
  } catch (error) {
    console.error('Error fetching faq:', error);
    res.status(500).send({
      success: false,
      message: 'Failed to fetch faq',
    });
  }
};

const getBlogs = async (req, res) => {
  try {
    const { blogCollection } = getCollections();
    const blog = await blogCollection.find().toArray();
    res.send({ success: true, data: blog });
  } catch (error) {
    console.error('Error fetching blog:', error);
    res.status(500).send({
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
