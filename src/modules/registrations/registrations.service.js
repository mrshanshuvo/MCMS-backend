const Registration = require('./registrations.model');
const Camp = require('../camps/camps.model');
const User = require('../users/users.model');

const escapeRegex = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const registerForCampInDB = async (registrationData) => {
  const { campId, participantName, participantEmail, age, phoneNumber, gender, emergencyContact } =
    registrationData;

  const existing = await Registration.findOne({ campId, participantEmail });
  if (existing) return { duplicate: true };

  const newRegistration = await Registration.create({
    campId,
    participantEmail,
    participantName: participantName || 'Anonymous',
    age: parseInt(age, 10),
    phoneNumber,
    gender,
    emergencyContact,
    registrationDate: new Date(),
    paymentStatus: 'Unpaid',
    confirmationStatus: 'Pending',
  });

  // Trigger Notification for Participant
  try {
    const { createNotification } = require('../notifications/notifications.service');
    await createNotification({
      userEmail: participantEmail,
      title: 'Registration Successful',
      message: `You successfully registered for the camp.`,
      type: 'registration',
      link: '/dashboard/registered-camps',
    });
  } catch (err) {
    console.error('Notification trigger error:', err);
  }

  return { success: true, registrationId: newRegistration._id };
};

const checkRegistrationInDB = async (campId, email) => {
  const registration = await Registration.findOne({ campId, participantEmail: email });
  return !!registration;
};

const deleteRegistrationInDB = async (id, requestingEmail) => {
  const registration = await Registration.findById(id);
  if (!registration) return null;

  const requestingUser = await User.findOne({ email: requestingEmail });

  if (registration.participantEmail !== requestingEmail && requestingUser?.role !== 'organizer') {
    return { forbidden: true };
  }

  await Registration.findByIdAndDelete(id);
  await Camp.findByIdAndUpdate(registration.campId, { $inc: { participantCount: -1 } });

  return { success: true };
};

const findAllRegistrationsInDB = async (queryParams) => {
  const {
    page = 1,
    limit = 10,
    search = '',
    status = 'all',
    campId,
    sortBy = 'registrationDate',
    sortOrder = 'desc',
  } = queryParams;

  const pageNumber = Math.max(parseInt(page, 10), 1);
  const limitNumber = Math.min(Math.max(parseInt(limit, 10), 1), 100);
  const sortDirection = sortOrder === 'asc' ? 1 : -1;

  const filter = {};
  if (status !== 'all') filter.confirmationStatus = status;
  if (campId) {
    const mongoose = require('mongoose');
    if (mongoose.Types.ObjectId.isValid(campId)) filter.campId = campId;
  }

  if (search) {
    const searchRegex = new RegExp(escapeRegex(search), 'i');
    filter.$or = [
      { participantName: searchRegex },
      { participantEmail: searchRegex },
      { transactionId: searchRegex },
    ];
  }

  const [totalCount, registrations] = await Promise.all([
    Registration.countDocuments(filter),
    Registration.find(filter)
      .sort({ [sortBy]: sortDirection })
      .skip((pageNumber - 1) * limitNumber)
      .limit(limitNumber)
      .lean(),
  ]);

  // Enrich with camp details
  const campIds = [...new Set(registrations.map((r) => r.campId?.toString()))];
  const camps = await Camp.find({ _id: { $in: campIds } }).lean();
  const campMap = camps.reduce((map, camp) => {
    map[camp._id.toString()] = camp;
    return map;
  }, {});

  const enrichedRegistrations = registrations.map((reg) => ({
    ...reg,
    campName: campMap[reg.campId?.toString()]?.name || 'Unknown Camp',
    campFees: campMap[reg.campId?.toString()]?.fees || 0,
    campLocation: campMap[reg.campId?.toString()]?.location || 'Unknown Location',
  }));

  return {
    data: enrichedRegistrations,
    pagination: {
      page: pageNumber,
      limit: limitNumber,
      totalCount,
      totalPages: Math.ceil(totalCount / limitNumber),
    },
  };
};

const cancelRegistrationInDB = async (campId, email) => {
  const registration = await Registration.findOne({ campId, participantEmail: email });
  if (!registration) return null;
  if (registration.paymentStatus === 'Paid') return { cannotCancel: true };

  await Registration.findByIdAndDelete(registration._id);
  await Camp.findByIdAndUpdate(campId, { $inc: { participantCount: -1 } });

  return { success: true };
};

const getParticipantAnalyticsInDB = async (email) => {
  return await Registration.aggregate([
    {
      $match: {
        participantEmail: email,
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
  ]);
};

module.exports = {
  registerForCampInDB,
  checkRegistrationInDB,
  deleteRegistrationInDB,
  findAllRegistrationsInDB,
  cancelRegistrationInDB,
  getParticipantAnalyticsInDB,
};
