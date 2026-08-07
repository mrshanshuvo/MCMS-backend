const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

const getCamps = async (req, res) => {
  try {
    const { search = '', sort = 'participantCount', page = '1', limit = '6' } = req.query;

    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    const searchRegex = new RegExp(search, 'i');

    const query = {
      $or: [
        { campName: { $regex: searchRegex } },
        { location: { $regex: searchRegex } },
        { healthcareProfessional: { $regex: searchRegex } },
      ],
    };

    let sortOption = {};
    switch (sort) {
      case 'participantCount':
        sortOption = { participantCount: -1 };
        break;
      case 'campFeesAsc':
        sortOption = { campFees: 1 };
        break;
      case 'campFeesDesc':
        sortOption = { campFees: -1 };
        break;
      case 'alphabetical':
        sortOption = { campName: 1 };
        break;
      default:
        sortOption = { participantCount: -1 };
    }

    const { campsCollection } = getCollections();
    const total = await campsCollection.countDocuments(query);

    const camps = await campsCollection
      .find(query)
      .sort(sortOption)
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .toArray();

    res.json({
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
      camps,
    });
  } catch (error) {
    console.error('Error fetching camps:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

const getCampById = async (req, res) => {
  try {
    const campId = req.params.id;

    if (!campId) {
      return res.status(400).json({ error: 'Camp ID is required' });
    }

    const { campsCollection } = getCollections();
    const objectId = new ObjectId(campId);
    const camp = await campsCollection.findOne({ _id: objectId });

    if (!camp) {
      return res.status(404).json({ error: 'Camp not found' });
    }

    res.json({ camp });
  } catch (error) {
    console.error('Error fetching camp by ID:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

const addCamp = async (req, res) => {
  try {
    const { campsCollection } = getCollections();
    const newCamp = req.body;
    newCamp.organizerEmail = req.user.email;
    newCamp.participantCount = 0;
    newCamp.createdAt = new Date();

    const result = await campsCollection.insertOne(newCamp);
    res.status(201).json({
      success: true,
      message: 'Camp added',
      campId: result.insertedId,
    });
  } catch (error) {
    console.error('Error adding camp:', error);
    res.status(500).json({ success: false, error: 'Failed to add camp' });
  }
};

const getOrganizerCamps = async (req, res) => {
  try {
    const { campsCollection } = getCollections();
    const organizerEmail = req.user.email;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;

    const query = { organizerEmail };

    const camps = await campsCollection.find(query).skip(skip).limit(limit).toArray();
    const totalCount = await campsCollection.countDocuments(query);

    res.json({
      camps,
      totalCount,
      currentPage: page,
      totalPages: Math.ceil(totalCount / limit),
    });
  } catch (error) {
    console.error('Error fetching organizer camps:', error);
    res.status(500).json({ error: 'Failed to fetch organizer camps' });
  }
};

const incrementParticipantCount = async (req, res) => {
  try {
    const campId = req.params.id;

    if (!ObjectId.isValid(campId)) {
      return res.status(400).json({ error: 'Invalid camp ID format' });
    }

    const { campsCollection } = getCollections();
    const result = await campsCollection.updateOne(
      { _id: new ObjectId(campId) },
      { $inc: { participantCount: 1 } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: 'Camp not found or count not updated' });
    }

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Increment Error:', error);
    res.status(500).json({ error: 'Failed to increment count' });
  }
};

const updateCamp = async (req, res) => {
  try {
    const { campId } = req.params;
    const updatedCamp = req.body;
    const { campsCollection } = getCollections();

    const camp = await campsCollection.findOne({
      _id: new ObjectId(campId),
      organizerEmail: req.user.email,
    });

    if (!camp) {
      return res.status(404).json({
        success: false,
        message: 'Camp not found or not owned by organizer',
      });
    }

    const result = await campsCollection.updateOne(
      { _id: new ObjectId(campId) },
      { $set: updatedCamp }
    );

    if (result.modifiedCount > 0) {
      res.json({ success: true });
    } else {
      res.json({
        success: false,
        message: 'Camp not found or no changes',
      });
    }
  } catch (error) {
    console.error('Error updating camp:', error);
    res.status(500).json({ success: false, error: error.message });
  }
};

const deleteCamp = async (req, res) => {
  try {
    const { campId } = req.params;
    const { campsCollection, registrationsCollection } = getCollections();

    const camp = await campsCollection.findOne({
      _id: new ObjectId(campId),
      organizerEmail: req.user.email,
    });

    if (!camp) {
      return res.status(404).json({
        success: false,
        message: 'Camp not found or not owned by organizer',
      });
    }

    const result = await campsCollection.deleteOne({
      _id: new ObjectId(campId),
    });

    if (result.deletedCount > 0) {
      await registrationsCollection.deleteMany({
        campId: new ObjectId(campId),
      });

      res.json({
        success: true,
        deletedCount: result.deletedCount,
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'Camp not found',
      });
    }
  } catch (error) {
    console.error('Error deleting camp:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete camp',
      details: error.message,
    });
  }
};

const getCampsWithRegistrations = async (req, res) => {
  try {
    const { campsCollection } = getCollections();
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;

    const [results, total] = await Promise.all([
      campsCollection
        .aggregate([
          {
            $lookup: {
              from: 'registrations',
              let: { campIdObj: '$_id' },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $and: [
                        { $eq: ['$campId', '$$campIdObj'] },
                        { $eq: ['$participantEmail', req.params.email] },
                      ],
                    },
                  },
                },
                {
                  $project: {
                    _id: 1,
                    participantName: 1,
                    paymentStatus: 1,
                    confirmationStatus: 1,
                    registrationDate: 1,
                  },
                },
              ],
              as: 'participants',
            },
          },
          { $match: { 'participants.0': { $exists: true } } },
          {
            $lookup: {
              from: 'feedback',
              let: { campIdObj: '$_id' },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $and: [
                        { $eq: ['$campId', '$$campIdObj'] },
                        { $eq: ['$participantEmail', req.params.email] },
                      ],
                    },
                  },
                },
                { $limit: 1 },
              ],
              as: 'userFeedback',
            },
          },
          {
            $addFields: {
              hasFeedback: { $gt: [{ $size: '$userFeedback' }, 0] },
            },
          },
          {
            $project: {
              _id: 1,
              name: 1,
              dateTime: 1,
              location: 1,
              fees: 1,
              healthcareProfessional: 1,
              participants: 1,
              hasFeedback: 1,
            },
          },
          { $skip: skip },
          { $limit: limit },
        ])
        .toArray(),
      campsCollection
        .aggregate([
          {
            $lookup: {
              from: 'registrations',
              let: { campIdObj: '$_id' },
              pipeline: [
                {
                  $match: {
                    $expr: {
                      $and: [
                        { $eq: ['$campId', '$$campIdObj'] },
                        { $eq: ['$participantEmail', req.params.email] },
                      ],
                    },
                  },
                },
              ],
              as: 'participants',
            },
          },
          { $match: { 'participants.0': { $exists: true } } },
          { $count: 'total' },
        ])
        .toArray(),
    ]);

    const totalCount = total[0]?.total || 0;

    res.json({ results, totalCount });
  } catch (error) {
    console.error('Error fetching camps:', error);
    res.status(500).json({ error: 'Failed to fetch camps data' });
  }
};

module.exports = {
  getCamps,
  getCampById,
  addCamp,
  getOrganizerCamps,
  incrementParticipantCount,
  updateCamp,
  deleteCamp,
  getCampsWithRegistrations,
};
