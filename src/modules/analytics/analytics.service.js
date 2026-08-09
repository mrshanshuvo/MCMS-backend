const Camp = require('../camps/camps.model');
const Registration = require('../registrations/registrations.model');
const Payment = require('../payments/payments.model');
const { Parser } = require('json2csv');

const getOrganizerOverviewInDB = async (organizerEmail) => {
  const organizerCamps = await Camp.find({ organizerEmail }).lean();
  const campIds = organizerCamps.map((c) => c._id);

  const [totalRegistrations, paidPayments, monthlyRevenue] = await Promise.all([
    Registration.countDocuments({ campId: { $in: campIds } }),
    Payment.aggregate([
      { $match: { campId: { $in: campIds }, status: 'Completed' } },
      { $group: { _id: null, totalRevenue: { $sum: '$amount' }, count: { $sum: 1 } } },
    ]),
    Payment.aggregate([
      { $match: { campId: { $in: campIds }, status: 'Completed' } },
      {
        $group: {
          _id: {
            year: { $year: '$paymentDate' },
            month: { $month: '$paymentDate' },
          },
          revenue: { $sum: '$amount' },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.year': -1, '_id.month': -1 } },
    ]),
  ]);

  const totalRevenue = paidPayments[0]?.totalRevenue || 0;
  const paidCount = paidPayments[0]?.count || 0;

  return {
    summary: {
      totalCamps: organizerCamps.length,
      totalRegistrations,
      paidCount,
      totalRevenue,
    },
    monthlyRevenue: monthlyRevenue.map((item) => ({
      year: item._id.year,
      month: item._id.month,
      revenue: item.revenue,
      transactions: item.count,
    })),
    campsBreakdown: organizerCamps.map((camp) => ({
      campId: camp._id,
      campName: camp.name,
      participantCount: camp.participantCount || 0,
      fees: camp.fees || 0,
    })),
  };
};

const exportRegistrationsCSVInDB = async (organizerEmail, campId) => {
  const mongoose = require('mongoose');
  const query = { organizerEmail };
  if (campId && mongoose.Types.ObjectId.isValid(campId)) {
    query._id = campId;
  }

  const organizerCamps = await Camp.find(query).lean();
  const campIds = organizerCamps.map((c) => c._id);
  const campMap = organizerCamps.reduce((acc, c) => {
    acc[c._id.toString()] = c.name;
    return acc;
  }, {});

  const registrations = await Registration.find({ campId: { $in: campIds } })
    .sort({ registrationDate: -1 })
    .lean();

  const formattedData = registrations.map((r) => ({
    Registration_ID: r._id.toString(),
    Camp_Name: campMap[r.campId?.toString()] || 'N/A',
    Participant_Name: r.participantName,
    Participant_Email: r.participantEmail,
    Age: r.age,
    Phone: r.phoneNumber,
    Gender: r.gender,
    Emergency_Contact: r.emergencyContact,
    Payment_Status: r.paymentStatus,
    Confirmation_Status: r.confirmationStatus,
    Registration_Date: r.registrationDate ? new Date(r.registrationDate).toISOString() : '',
  }));

  const fields = [
    'Registration_ID',
    'Camp_Name',
    'Participant_Name',
    'Participant_Email',
    'Age',
    'Phone',
    'Gender',
    'Emergency_Contact',
    'Payment_Status',
    'Confirmation_Status',
    'Registration_Date',
  ];

  const json2csvParser = new Parser({ fields });
  return json2csvParser.parse(formattedData);
};

const exportPaymentsCSVInDB = async (organizerEmail) => {
  const organizerCamps = await Camp.find({ organizerEmail }).lean();
  const campIds = organizerCamps.map((c) => c._id);
  const campMap = organizerCamps.reduce((acc, c) => {
    acc[c._id.toString()] = c.name;
    return acc;
  }, {});

  const payments = await Payment.find({ campId: { $in: campIds } })
    .sort({ paymentDate: -1 })
    .lean();

  const formattedData = payments.map((p) => ({
    Payment_ID: p._id.toString(),
    Camp_Name: campMap[p.campId?.toString()] || 'N/A',
    Participant_Email: p.participantEmail,
    Transaction_ID: p.transactionId,
    Amount_USD: p.amount,
    Payment_Method: p.paymentMethod || 'Stripe',
    Status: p.status,
    Payment_Date: p.paymentDate ? new Date(p.paymentDate).toISOString() : '',
  }));

  const fields = [
    'Payment_ID',
    'Camp_Name',
    'Participant_Email',
    'Transaction_ID',
    'Amount_USD',
    'Payment_Method',
    'Status',
    'Payment_Date',
  ];

  const json2csvParser = new Parser({ fields });
  return json2csvParser.parse(formattedData);
};

module.exports = {
  getOrganizerOverviewInDB,
  exportRegistrationsCSVInDB,
  exportPaymentsCSVInDB,
};
