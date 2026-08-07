const { ObjectId } = require('mongodb');
const { getCollections } = require('../../config/db');

const registerForCamp = async (req, res) => {
  try {
    const {
      campId,
      participantName,
      participantEmail,
      age,
      phoneNumber,
      gender,
      emergencyContact,
    } = req.body;

    if (!campId || !participantEmail || !age || !phoneNumber || !gender || !emergencyContact) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!ObjectId.isValid(campId)) {
      return res.status(400).json({ error: 'Invalid campId format' });
    }

    const { registrationsCollection } = getCollections();

    const existing = await registrationsCollection.findOne({
      campId: new ObjectId(campId),
      participantEmail,
    });

    if (existing) {
      return res.status(400).json({ error: 'Already registered for this camp' });
    }

    const newRegistration = {
      campId: new ObjectId(campId),
      participantEmail,
      participantName: participantName || 'Anonymous',
      age: parseInt(age),
      phoneNumber,
      gender,
      emergencyContact,
      registrationDate: new Date(),
      paymentStatus: 'Unpaid',
      confirmationStatus: 'Pending',
      transactionId: new ObjectId(),
    };

    const result = await registrationsCollection.insertOne(newRegistration);
    res.status(201).json({ success: true, registrationId: result.insertedId });
  } catch (error) {
    console.error('Registration Error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Duplicate registration detected' });
    }
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
};

const checkRegistration = async (req, res) => {
  try {
    const { campId } = req.query;
    const { registrationsCollection } = getCollections();
    const registration = await registrationsCollection.findOne({
      campId: new ObjectId(campId),
      participantEmail: req.user.email,
    });
    res.json({ registered: !!registration });
  } catch (error) {
    console.error('Error checking registration:', error);
    res.status(500).json({ error: 'Failed to check registration' });
  }
};

const deleteRegistration = async (req, res) => {
  try {
    const { id } = req.params;
    const { registrationsCollection } = getCollections();
    const result = await registrationsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Registration not found' });
    }

    res.json({ message: 'Registration deleted successfully' });
  } catch (error) {
    console.error('Error deleting registration:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

const getAllRegistrations = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      search = '',
      status = 'all',
      campId,
      sortBy = 'registrationDate',
      sortOrder = 'desc',
    } = req.query;

    const pageNumber = Math.max(parseInt(page), 1);
    const limitNumber = Math.min(Math.max(parseInt(limit), 1), 100);
    const sortDirection = sortOrder === 'asc' ? 1 : -1;

    const filter = {};

    if (status !== 'all') {
      filter.status = status;
    }

    if (campId) {
      filter.campId = new ObjectId(campId);
    }

    if (search) {
      const searchRegex = new RegExp(search, 'i');
      filter.$or = [
        { participantName: searchRegex },
        { participantEmail: searchRegex },
        { transactionId: searchRegex },
      ];
    }

    const { registrationsCollection, campsCollection } = getCollections();
    const totalCount = await registrationsCollection.countDocuments(filter);

    const registrations = await registrationsCollection
      .find(filter)
      .sort({ [sortBy]: sortDirection })
      .skip((pageNumber - 1) * limitNumber)
      .limit(limitNumber)
      .toArray();

    const campIds = [...new Set(registrations.map((r) => r.campId))];
    const camps = await campsCollection
      .find({
        _id: { $in: campIds },
      })
      .toArray();

    const campMap = camps.reduce((map, camp) => {
      map[camp._id] = camp;
      return map;
    }, {});

    const enrichedRegistrations = registrations.map((reg) => ({
      ...reg,
      campName: campMap[reg.campId]?.name || 'Unknown Camp',
      campFees: campMap[reg.campId]?.fees || 0,
      campLocation: campMap[reg.campId]?.location || 'Unknown Location',
    }));

    res.status(200).json({
      success: true,
      data: enrichedRegistrations,
      pagination: {
        page: pageNumber,
        limit: limitNumber,
        totalCount,
        totalPages: Math.ceil(totalCount / limitNumber),
      },
    });
  } catch (error) {
    console.error('Failed to get registrations:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch registrations',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};

const cancelRegistration = async (req, res) => {
  try {
    const { campId } = req.params;
    const { email } = req.user;
    const { registrationsCollection, campsCollection } = getCollections();

    const registration = await registrationsCollection.findOne({
      campId: new ObjectId(campId),
      participantEmail: email,
    });

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    if (registration.paymentStatus === 'Paid') {
      return res.status(400).json({
        error: 'Cannot cancel after payment. Please contact support.',
      });
    }

    await registrationsCollection.deleteOne({
      _id: registration._id,
    });

    await campsCollection.updateOne(
      { _id: new ObjectId(campId) },
      { $inc: { participantCount: -1 } }
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Error cancelling registration:', error);
    res.status(500).json({ error: 'Failed to cancel registration' });
  }
};

const getParticipantAnalytics = async (req, res) => {
  try {
    const { registrationsCollection } = getCollections();
    const analytics = await registrationsCollection
      .aggregate([
        {
          $match: {
            participantEmail: req.user.email,
            paymentStatus: 'Paid',
          },
        },
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
            _id: 0,
            campName: '$camp.name',
            date: '$camp.dateTime',
            fees: '$camp.fees',
            status: '$confirmationStatus',
            paymentDate: 1,
          },
        },
        { $sort: { paymentDate: -1 } },
      ])
      .toArray();

    res.json({
      success: true,
      data: analytics,
    });
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch analytics',
    });
  }
};

module.exports = {
  registerForCamp,
  checkRegistration,
  deleteRegistration,
  getAllRegistrations,
  cancelRegistration,
  getParticipantAnalytics,
};
