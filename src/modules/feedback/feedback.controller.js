const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

const submitFeedback = async (req, res) => {
  try {
    const { campId, rating, feedback, name, photoURL } = req.body;

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1-5' });
    }

    const { registrationsCollection, feedbackCollection } = getCollections();

    const registration = await registrationsCollection.findOne({
      campId: new ObjectId(campId),
      participantEmail: req.user.email,
      paymentStatus: 'Paid',
    });

    if (!registration) {
      return res.status(403).json({ error: 'You must attend the camp to provide feedback' });
    }

    const existing = await feedbackCollection.findOne({
      campId: new ObjectId(campId),
      participantEmail: req.user.email,
    });

    if (existing) {
      return res.status(400).json({ error: 'Feedback already submitted' });
    }

    await feedbackCollection.insertOne({
      campId: new ObjectId(campId),
      participantEmail: req.user.email,
      participantName: name || 'Anonymous',
      participantPhotoURL: photoURL,
      rating,
      feedback,
      date: new Date(),
    });

    res.status(201).json({ success: true });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
};

const getFeedback = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 5;
    const { feedbackCollection } = getCollections();

    const feedback = await feedbackCollection
      .aggregate([
        {
          $lookup: {
            from: 'camps',
            localField: 'campId',
            foreignField: '_id',
            as: 'camp',
          },
        },
        { $unwind: '$camp' },
        {
          $project: {
            _id: 1,
            rating: 1,
            feedback: 1,
            date: 1,
            participantName: 1,
            participantPhotoURL: 1,
            campName: '$camp.name',
          },
        },
        { $sort: { date: -1 } },
        { $limit: limit },
      ])
      .toArray();

    res.json(feedback);
  } catch (error) {
    console.error('Feedback fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch feedback' });
  }
};

module.exports = {
  submitFeedback,
  getFeedback,
};
