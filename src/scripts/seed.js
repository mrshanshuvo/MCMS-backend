require('dotenv').config();
const { connectDB, dbConnection } = require('../config/db');

const User = require('../modules/users/users.model');
const Camp = require('../modules/camps/camps.model');
const Registration = require('../modules/registrations/registrations.model');
const Payment = require('../modules/payments/payments.model');
const Feedback = require('../modules/feedback/feedback.model');
const Notification = require('../modules/notifications/notifications.model');
const SuccessStory = require('../modules/public/success-story.model');
const Faq = require('../modules/public/faq.model');
const Blog = require('../modules/public/blog.model');

const { getUsersSeedData } = require('./seeds/users.seed');
const { campsData } = require('./seeds/camps.seed');
const { getRegistrationsSeedData } = require('./seeds/registrations.seed');
const { getPaymentsSeedData } = require('./seeds/payments.seed');
const { getFeedbackSeedData } = require('./seeds/feedback.seed');
const { getNotificationsSeedData } = require('./seeds/notifications.seed');
const { successStoriesData, faqsData, blogsData } = require('./seeds/public.seed');

async function seedMasterData() {
  try {
    console.log('Connecting to database for master seeding...');
    await connectDB();

    // 1. Users
    console.log('Seeding Users...');
    const usersData = await getUsersSeedData();
    const seededUsers = [];
    for (const u of usersData) {
      const userDoc = await User.findOneAndUpdate(
        { email: u.email },
        { $set: u },
        { upsert: true, returnDocument: 'after' }
      );
      seededUsers.push(userDoc);
    }
    console.log(`Seeded ${seededUsers.length} Users.`);

    // 2. Camps
    console.log('Seeding Camps...');
    await Camp.deleteMany({});
    const seededCamps = await Camp.insertMany(campsData);
    console.log(`Seeded ${seededCamps.length} Camps.`);

    // 3. Registrations
    console.log('Seeding Registrations...');
    await Registration.deleteMany({});
    const participantsList = seededUsers.filter((u) => u.role === 'participant');
    const registrationsData = getRegistrationsSeedData(seededCamps, participantsList);
    const seededRegistrations = await Registration.insertMany(registrationsData);
    console.log(`Seeded ${seededRegistrations.length} Registrations.`);

    // 4. Payments
    console.log('Seeding Payments...');
    await Payment.deleteMany({});
    const paymentsData = getPaymentsSeedData(seededCamps, seededRegistrations, participantsList);
    const seededPayments = await Payment.insertMany(paymentsData);
    console.log(`Seeded ${seededPayments.length} Payments.`);

    // 5. Feedback
    console.log('Seeding Feedback...');
    await Feedback.deleteMany({});
    const feedbackData = getFeedbackSeedData(seededCamps, participantsList);
    const seededFeedback = await Feedback.insertMany(feedbackData);
    console.log(`Seeded ${seededFeedback.length} Feedback entries.`);

    // 6. Notifications
    console.log('Seeding Notifications...');
    await Notification.deleteMany({});
    const notificationsData = getNotificationsSeedData(participantsList);
    const seededNotifications = await Notification.insertMany(notificationsData);
    console.log(`Seeded ${seededNotifications.length} Notifications.`);

    // 7. Success Stories
    console.log('Seeding Success Stories...');
    await SuccessStory.deleteMany({});
    const seededSuccessStories = await SuccessStory.insertMany(successStoriesData);
    console.log(`Seeded ${seededSuccessStories.length} Success Stories.`);

    // 8. FAQs
    console.log('Seeding FAQs...');
    await Faq.deleteMany({});
    const seededFaqs = await Faq.insertMany(faqsData);
    console.log(`Seeded ${seededFaqs.length} FAQs.`);

    // 9. Blogs
    console.log('Seeding Blogs...');
    await Blog.deleteMany({});
    const seededBlogs = await Blog.insertMany(blogsData);
    console.log(`Seeded ${seededBlogs.length} Blogs.`);

    console.log('\n======================================================');
    console.log('✅ MASTER DATABASE SEEDING COMPLETED SUCCESSFULLY!');
    console.log('• Users:           10');
    console.log('• Camps:           10');
    console.log('• Registrations:   10');
    console.log('• Payments:        10');
    console.log('• Feedback:        10');
    console.log('• Notifications:   10');
    console.log('• Success Stories: 10');
    console.log('• FAQs:            10');
    console.log('• Blogs:           10');
    console.log('======================================================\n');

    await dbConnection.close();
    process.exit(0);
  } catch (error) {
    console.error('❌ Master seeding failed:', error);
    process.exit(1);
  }
}

seedMasterData();
