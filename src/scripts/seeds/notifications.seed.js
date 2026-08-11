function getNotificationsSeedData(participantsList) {
  return [
    {
      userEmail: participantsList[0].email,
      title: 'Registration Confirmed',
      message: 'Your registration for Cardiology Health & Vitality Camp is confirmed.',
      read: true,
      createdAt: new Date('2026-08-01'),
    },
    {
      userEmail: participantsList[0].email,
      title: 'Payment Successful',
      message: 'Payment of $50 for Cardiology Camp received with Txn ID: txn_1001.',
      read: true,
      createdAt: new Date('2026-08-01'),
    },
    {
      userEmail: participantsList[1].email,
      title: 'Registration Confirmed',
      message: 'Your registration for Cardiology Health & Vitality Camp is confirmed.',
      read: false,
      createdAt: new Date('2026-08-02'),
    },
    {
      userEmail: participantsList[2].email,
      title: 'Registration Confirmed',
      message: 'Your registration for Cardiology Health & Vitality Camp is confirmed.',
      read: false,
      createdAt: new Date('2026-08-03'),
    },
    {
      userEmail: participantsList[3].email,
      title: 'Payment Pending',
      message: 'Please complete your payment to confirm registration for Cardiology Camp.',
      read: false,
      createdAt: new Date('2026-08-04'),
    },
    {
      userEmail: participantsList[0].email,
      title: 'Upcoming Camp Reminder',
      message: 'Vision & Eye Care Wellness Camp starts in 5 days!',
      read: false,
      createdAt: new Date('2026-08-05'),
    },
    {
      userEmail: participantsList[4].email,
      title: 'Registration Confirmed',
      message: 'Your spot at Vision & Eye Care Wellness Camp is locked in.',
      read: true,
      createdAt: new Date('2026-08-06'),
    },
    {
      userEmail: participantsList[6].email,
      title: 'Pediatric Camp Details',
      message: 'Please bring your child immunisation records to the camp.',
      read: false,
      createdAt: new Date('2026-08-08'),
    },
    {
      userEmail: participantsList[7].email,
      title: 'Payment Confirmation',
      message: 'Payment of $25 received for Pediatric Health Checkup.',
      read: true,
      createdAt: new Date('2026-08-09'),
    },
    {
      userEmail: 'organizer@carecamp.com',
      title: 'New Camp Registrations',
      message: 'Cardiology Health & Vitality Camp reached 4 registered participants.',
      read: false,
      createdAt: new Date('2026-08-10'),
    },
  ];
}

module.exports = { getNotificationsSeedData };
