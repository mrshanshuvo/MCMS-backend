const SuccessStory = require('./success-story.model');
const Faq = require('./faq.model');
const Blog = require('./blog.model');

const findSuccessStoriesInDB = async () => {
  return await SuccessStory.find().lean();
};

const findFaqsInDB = async () => {
  return await Faq.find().lean();
};

const findBlogsInDB = async () => {
  return await Blog.find().lean();
};

module.exports = {
  findSuccessStoriesInDB,
  findFaqsInDB,
  findBlogsInDB,
};
