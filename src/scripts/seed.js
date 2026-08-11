require('dotenv').config();
const bcrypt = require('bcryptjs');
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

async function seedMasterData() {
  try {
    console.log('Connecting to database for master seeding...');
    await connectDB();

    // -------------------------------------------------------------
    // 1. SEED USERS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Users...');
    const hashedPass = await bcrypt.hash('Password123!', 10);

    const usersData = [
      {
        email: 'organizer@carecamp.com',
        password: hashedPass,
        name: 'Dr. Sarah Connor',
        photoURL: 'https://images.unsplash.com/photo-1559839734-2b71ea197ec2?w=150',
        role: 'organizer',
        phone: '+1 555-0199',
        address: 'CareCamp HQ, Medical Tower, NY',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'admin@carecamp.com',
        password: hashedPass,
        name: 'Dr. Marcus Vance',
        photoURL: 'https://images.unsplash.com/photo-1622253692010-333f2da6031d?w=150',
        role: 'organizer',
        phone: '+1 555-0100',
        address: '100 Admin Plaza, Boston, MA',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'participant@carecamp.com',
        password: hashedPass,
        name: 'John Doe',
        photoURL: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150',
        role: 'participant',
        phone: '+1 555-0144',
        address: '123 Health Ave, Los Angeles, CA',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'sarah.smith@yahoo.com',
        password: hashedPass,
        name: 'Sarah Smith',
        photoURL: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150',
        role: 'participant',
        phone: '+1 555-0155',
        address: '456 Oak Street, Chicago, IL',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'michael.brown@outlook.com',
        password: hashedPass,
        name: 'Michael Brown',
        photoURL: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150',
        role: 'participant',
        phone: '+1 555-0166',
        address: '789 Pine Road, Houston, TX',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'emily.davis@health.org',
        password: hashedPass,
        name: 'Emily Davis',
        photoURL: 'https://images.unsplash.com/photo-1438761681033-6461ffad8d80?w=150',
        role: 'participant',
        phone: '+1 555-0177',
        address: '321 Maple Ave, Phoenix, AZ',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'david.wilson@clinic.net',
        password: hashedPass,
        name: 'David Wilson',
        photoURL: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150',
        role: 'participant',
        phone: '+1 555-0188',
        address: '654 Elm Court, Philadelphia, PA',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'jessica.taylor@medical.com',
        password: hashedPass,
        name: 'Jessica Taylor',
        photoURL: 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=150',
        role: 'participant',
        phone: '+1 555-0190',
        address: '987 Cedar Blvd, San Antonio, TX',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'james.anderson@wellness.org',
        password: hashedPass,
        name: 'James Anderson',
        photoURL: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=150',
        role: 'participant',
        phone: '+1 555-0191',
        address: '147 Spruce Lane, San Diego, CA',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
      {
        email: 'amanda.white@care.com',
        password: hashedPass,
        name: 'Amanda White',
        photoURL: 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=150',
        role: 'participant',
        phone: '+1 555-0192',
        address: '258 Birch St, Dallas, TX',
        created_at: new Date().toISOString(),
        last_login: new Date().toISOString(),
      },
    ];

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

    // -------------------------------------------------------------
    // 2. SEED CAMPS / ITEMS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Camps...');
    await Camp.deleteMany({});

    const campsData = [
      {
        name: 'Cardiology Health & Vitality Camp',
        location: 'Central Community Hospital, NY',
        fees: 50,
        dateTime: '2026-09-15 09:00 AM',
        healthcareProfessional: 'Dr. Robert Chen (Cardiologist)',
        description:
          'Comprehensive cardiovascular screening, blood pressure monitoring, and heart wellness advice.',
        image: 'https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?w=600',
        organizerEmail: 'organizer@carecamp.com',
        participantCount: 4,
      },
      {
        name: 'Vision & Eye Care Wellness Camp',
        location: 'Community Center, Los Angeles, CA',
        fees: 0,
        dateTime: '2026-09-20 10:00 AM',
        healthcareProfessional: 'Dr. Emily Vance (Ophthalmologist)',
        description:
          'Free vision testing, glaucoma screening, and prescription consultations for all ages.',
        image: 'https://images.unsplash.com/photo-1584515979956-d9f6e5d09982?w=600',
        organizerEmail: 'organizer@carecamp.com',
        participantCount: 3,
      },
      {
        name: 'Pediatric Health Checkup & Vaccination',
        location: 'St. Jude Children Wing, Chicago, IL',
        fees: 25,
        dateTime: '2026-09-25 08:30 AM',
        healthcareProfessional: 'Dr. Maria Rodriguez (Pediatrician)',
        description: 'Growth monitoring, seasonal flu vaccinations, and child nutrition guidance.',
        image: 'https://images.unsplash.com/photo-1581594693702-fbdc51b2763b?w=600',
        organizerEmail: 'organizer@carecamp.com',
        participantCount: 2,
      },
      {
        name: 'Dental Care & Smile Restoration Camp',
        location: 'Downtown Dental Clinic, Houston, TX',
        fees: 30,
        dateTime: '2026-10-01 09:00 AM',
        healthcareProfessional: 'Dr. Alan Harper (DDS)',
        description:
          'Teeth cleaning, cavity checks, oral hygiene workshops, and free dental hygiene kits.',
        image: 'https://images.unsplash.com/photo-1606811841689-23dfddce3e95?w=600',
        organizerEmail: 'admin@carecamp.com',
        participantCount: 1,
      },
      {
        name: 'Orthopedic & Joint Health Camp',
        location: 'Sports Rehab Facility, Phoenix, AZ',
        fees: 40,
        dateTime: '2026-10-05 11:00 AM',
        healthcareProfessional: 'Dr. James Thorne (Orthopedic Specialist)',
        description:
          'Bone density assessments, joint mobility tests, and arthritis care consultations.',
        image: 'https://images.unsplash.com/photo-1579684385127-1ef15d508118?w=600',
        organizerEmail: 'admin@carecamp.com',
        participantCount: 0,
      },
      {
        name: 'Diabetes & Endocrine Health Awareness',
        location: 'Metabolic Care Center, Philadelphia, PA',
        fees: 15,
        dateTime: '2026-10-10 09:30 AM',
        healthcareProfessional: 'Dr. Priya Sharma (Endocrinologist)',
        description: 'HbA1c testing, blood glucose checks, and personalized diabetic diet plans.',
        image: 'https://images.unsplash.com/photo-1505751172876-fa1923c5c528?w=600',
        organizerEmail: 'organizer@carecamp.com',
        participantCount: 0,
      },
      {
        name: 'Dermatology & Skin Care Wellness Camp',
        location: 'Skin Institute, San Antonio, TX',
        fees: 35,
        dateTime: '2026-10-15 10:00 AM',
        healthcareProfessional: 'Dr. Sophia Martinez (Dermatologist)',
        description: 'Skin cancer screening, eczema management, and sun protection counseling.',
        image: 'https://images.unsplash.com/photo-1629909613654-28e377c37b09?w=600',
        organizerEmail: 'admin@carecamp.com',
        participantCount: 0,
      },
      {
        name: 'ENT & Hearing Care Camp',
        location: 'Audiology Center, San Diego, CA',
        fees: 20,
        dateTime: '2026-10-20 09:00 AM',
        healthcareProfessional: 'Dr. William Blake (ENT Specialist)',
        description: 'Hearing evaluations, ear wax removal, and sinus consultations.',
        image: 'https://images.unsplash.com/photo-1516549655169-df83a0774514?w=600',
        organizerEmail: 'organizer@carecamp.com',
        participantCount: 0,
      },
      {
        name: 'Neurology & Memory Wellness Checkup',
        location: 'Brain & Spine Institute, Boston, MA',
        fees: 60,
        dateTime: '2026-10-25 01:00 PM',
        healthcareProfessional: 'Dr. Arthur Pendelton (Neurologist)',
        description: 'Cognitive assessments, stroke prevention screening, and reflex testing.',
        image: 'https://images.unsplash.com/photo-1551076805-e1869033e561?w=600',
        organizerEmail: 'admin@carecamp.com',
        participantCount: 0,
      },
      {
        name: 'Women Medical Wellness & Gynecological Camp',
        location: 'Grace Women Hospital, Dallas, TX',
        fees: 0,
        dateTime: '2026-11-01 09:00 AM',
        healthcareProfessional: 'Dr. Rebecca Foster (OB/GYN)',
        description:
          'Free cervical screening, mammogram consultations, and maternal wellness workshops.',
        image: 'https://images.unsplash.com/photo-1532938911079-1b06ac7ceec7?w=600',
        organizerEmail: 'organizer@carecamp.com',
        participantCount: 0,
      },
    ];

    const seededCamps = await Camp.insertMany(campsData);
    console.log(`Seeded ${seededCamps.length} Camps.`);

    // -------------------------------------------------------------
    // 3. SEED REGISTRATIONS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Registrations...');
    await Registration.deleteMany({});

    const participantsList = seededUsers.filter((u) => u.role === 'participant');
    const registrationsData = [
      {
        campId: seededCamps[0]._id,
        participantEmail: participantsList[0].email,
        participantName: participantsList[0].name,
        age: 34,
        phoneNumber: '+1 555-0144',
        gender: 'Male',
        emergencyContact: '+1 555-9999',
        registrationDate: new Date('2026-08-01'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1001',
      },
      {
        campId: seededCamps[0]._id,
        participantEmail: participantsList[1].email,
        participantName: participantsList[1].name,
        age: 29,
        phoneNumber: '+1 555-0155',
        gender: 'Female',
        emergencyContact: '+1 555-8888',
        registrationDate: new Date('2026-08-02'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1002',
      },
      {
        campId: seededCamps[0]._id,
        participantEmail: participantsList[2].email,
        participantName: participantsList[2].name,
        age: 45,
        phoneNumber: '+1 555-0166',
        gender: 'Male',
        emergencyContact: '+1 555-7777',
        registrationDate: new Date('2026-08-03'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1003',
      },
      {
        campId: seededCamps[0]._id,
        participantEmail: participantsList[3].email,
        participantName: participantsList[3].name,
        age: 38,
        phoneNumber: '+1 555-0177',
        gender: 'Female',
        emergencyContact: '+1 555-6666',
        registrationDate: new Date('2026-08-04'),
        paymentStatus: 'Unpaid',
        confirmationStatus: 'Pending',
        transactionId: 'txn_1004_unpaid',
      },
      {
        campId: seededCamps[1]._id,
        participantEmail: participantsList[0].email,
        participantName: participantsList[0].name,
        age: 34,
        phoneNumber: '+1 555-0144',
        gender: 'Male',
        emergencyContact: '+1 555-9999',
        registrationDate: new Date('2026-08-05'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1005',
      },
      {
        campId: seededCamps[1]._id,
        participantEmail: participantsList[4].email,
        participantName: participantsList[4].name,
        age: 52,
        phoneNumber: '+1 555-0188',
        gender: 'Male',
        emergencyContact: '+1 555-5555',
        registrationDate: new Date('2026-08-06'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1006',
      },
      {
        campId: seededCamps[1]._id,
        participantEmail: participantsList[5].email,
        participantName: participantsList[5].name,
        age: 27,
        phoneNumber: '+1 555-0190',
        gender: 'Female',
        emergencyContact: '+1 555-4444',
        registrationDate: new Date('2026-08-07'),
        paymentStatus: 'Unpaid',
        confirmationStatus: 'Pending',
        transactionId: 'txn_1007_unpaid',
      },
      {
        campId: seededCamps[2]._id,
        participantEmail: participantsList[6].email,
        participantName: participantsList[6].name,
        age: 41,
        phoneNumber: '+1 555-0191',
        gender: 'Male',
        emergencyContact: '+1 555-3333',
        registrationDate: new Date('2026-08-08'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1008',
      },
      {
        campId: seededCamps[2]._id,
        participantEmail: participantsList[7].email,
        participantName: participantsList[7].name,
        age: 31,
        phoneNumber: '+1 555-0192',
        gender: 'Female',
        emergencyContact: '+1 555-2222',
        registrationDate: new Date('2026-08-09'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1009',
      },
      {
        campId: seededCamps[3]._id,
        participantEmail: participantsList[0].email,
        participantName: participantsList[0].name,
        age: 34,
        phoneNumber: '+1 555-0144',
        gender: 'Male',
        emergencyContact: '+1 555-9999',
        registrationDate: new Date('2026-08-10'),
        paymentStatus: 'Paid',
        confirmationStatus: 'Confirmed',
        transactionId: 'txn_1010',
      },
    ];

    const seededRegistrations = await Registration.insertMany(registrationsData);
    console.log(`Seeded ${seededRegistrations.length} Registrations.`);

    // -------------------------------------------------------------
    // 4. SEED PAYMENTS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Payments...');
    await Payment.deleteMany({});

    const paymentsData = [
      {
        campId: seededCamps[0]._id,
        registrationId: seededRegistrations[0]._id,
        participantEmail: participantsList[0].email,
        transactionId: 'txn_1001',
        amount: 50,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-01'),
        status: 'Completed',
      },
      {
        campId: seededCamps[0]._id,
        registrationId: seededRegistrations[1]._id,
        participantEmail: participantsList[1].email,
        transactionId: 'txn_1002',
        amount: 50,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-02'),
        status: 'Completed',
      },
      {
        campId: seededCamps[0]._id,
        registrationId: seededRegistrations[2]._id,
        participantEmail: participantsList[2].email,
        transactionId: 'txn_1003',
        amount: 50,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-03'),
        status: 'Completed',
      },
      {
        campId: seededCamps[1]._id,
        registrationId: seededRegistrations[4]._id,
        participantEmail: participantsList[0].email,
        transactionId: 'txn_1005',
        amount: 0,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-05'),
        status: 'Completed',
      },
      {
        campId: seededCamps[1]._id,
        registrationId: seededRegistrations[5]._id,
        participantEmail: participantsList[4].email,
        transactionId: 'txn_1006',
        amount: 0,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-06'),
        status: 'Completed',
      },
      {
        campId: seededCamps[2]._id,
        registrationId: seededRegistrations[7]._id,
        participantEmail: participantsList[6].email,
        transactionId: 'txn_1008',
        amount: 25,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-08'),
        status: 'Completed',
      },
      {
        campId: seededCamps[2]._id,
        registrationId: seededRegistrations[8]._id,
        participantEmail: participantsList[7].email,
        transactionId: 'txn_1009',
        amount: 25,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-09'),
        status: 'Completed',
      },
      {
        campId: seededCamps[3]._id,
        registrationId: seededRegistrations[9]._id,
        participantEmail: participantsList[0].email,
        transactionId: 'txn_1010',
        amount: 30,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-10'),
        status: 'Completed',
      },
      {
        campId: seededCamps[4]._id,
        registrationId: seededRegistrations[3]._id,
        participantEmail: participantsList[3].email,
        transactionId: 'txn_1011_pending',
        amount: 40,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-11'),
        status: 'Pending',
      },
      {
        campId: seededCamps[5]._id,
        registrationId: seededRegistrations[6]._id,
        participantEmail: participantsList[5].email,
        transactionId: 'txn_1012_pending',
        amount: 15,
        paymentMethod: 'Stripe',
        paymentDate: new Date('2026-08-11'),
        status: 'Pending',
      },
    ];

    const seededPayments = await Payment.insertMany(paymentsData);
    console.log(`Seeded ${seededPayments.length} Payments.`);

    // -------------------------------------------------------------
    // 5. SEED FEEDBACK (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Feedback...');
    await Feedback.deleteMany({});

    const feedbackData = [
      {
        campId: seededCamps[0]._id,
        participantEmail: participantsList[0].email,
        participantName: participantsList[0].name,
        participantPhotoURL: participantsList[0].photoURL,
        rating: 5,
        feedback:
          'Outstanding cardiology checkup! The doctors were extremely patient and explained my ECG results clearly.',
        date: new Date('2026-08-05'),
      },
      {
        campId: seededCamps[0]._id,
        participantEmail: participantsList[1].email,
        participantName: participantsList[1].name,
        participantPhotoURL: participantsList[1].photoURL,
        rating: 5,
        feedback:
          'Very well organized medical camp. The queue moved quickly and staff were helpful.',
        date: new Date('2026-08-06'),
      },
      {
        campId: seededCamps[1]._id,
        participantEmail: participantsList[0].email,
        participantName: participantsList[0].name,
        participantPhotoURL: participantsList[0].photoURL,
        rating: 4,
        feedback:
          'Free eye care camp was fantastic. Received my prescription reading glasses right on site!',
        date: new Date('2026-08-07'),
      },
      {
        campId: seededCamps[1]._id,
        participantEmail: participantsList[4].email,
        participantName: participantsList[4].name,
        participantPhotoURL: participantsList[4].photoURL,
        rating: 5,
        feedback: 'Great vision screening. Highly recommend CareCamp events to everyone in LA.',
        date: new Date('2026-08-08'),
      },
      {
        campId: seededCamps[2]._id,
        participantEmail: participantsList[6].email,
        participantName: participantsList[6].name,
        participantPhotoURL: participantsList[6].photoURL,
        rating: 5,
        feedback:
          'Brought my kids for pediatric checkup. Dr. Maria was gentle and made the kids feel safe.',
        date: new Date('2026-08-09'),
      },
      {
        campId: seededCamps[2]._id,
        participantEmail: participantsList[7].email,
        participantName: participantsList[7].name,
        participantPhotoURL: participantsList[7].photoURL,
        rating: 4,
        feedback: 'Smooth vaccination process and comprehensive child health guide provided.',
        date: new Date('2026-08-09'),
      },
      {
        campId: seededCamps[3]._id,
        participantEmail: participantsList[0].email,
        participantName: participantsList[0].name,
        participantPhotoURL: participantsList[0].photoURL,
        rating: 5,
        feedback: 'Dental cleaning was top notch! Appreciate the complimentary dental hygiene kit.',
        date: new Date('2026-08-10'),
      },
      {
        campId: seededCamps[4]._id,
        participantEmail: participantsList[2].email,
        participantName: participantsList[2].name,
        participantPhotoURL: participantsList[2].photoURL,
        rating: 4,
        feedback:
          'Informatve orthopedic session. The joint exercises shared by Dr. Thorne really helped my knee pain.',
        date: new Date('2026-08-10'),
      },
      {
        campId: seededCamps[5]._id,
        participantEmail: participantsList[3].email,
        participantName: participantsList[3].name,
        participantPhotoURL: participantsList[3].photoURL,
        rating: 5,
        feedback:
          'HbA1c screening was quick and results were delivered immediately with diet advice.',
        date: new Date('2026-08-11'),
      },
      {
        campId: seededCamps[6]._id,
        participantEmail: participantsList[5].email,
        participantName: participantsList[5].name,
        participantPhotoURL: participantsList[5].photoURL,
        rating: 5,
        feedback:
          'Dermatologist gave great skin protection advice and recommended suitable products.',
        date: new Date('2026-08-11'),
      },
    ];

    const seededFeedback = await Feedback.insertMany(feedbackData);
    console.log(`Seeded ${seededFeedback.length} Feedback entries.`);

    // -------------------------------------------------------------
    // 6. SEED NOTIFICATIONS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Notifications...');
    await Notification.deleteMany({});

    const notificationsData = [
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

    const seededNotifications = await Notification.insertMany(notificationsData);
    console.log(`Seeded ${seededNotifications.length} Notifications.`);

    // -------------------------------------------------------------
    // 7. SEED SUCCESS STORIES (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Success Stories...');
    await SuccessStory.deleteMany({});

    const successStoriesData = [
      {
        title: 'Early Detection Saved My Life',
        patientName: 'Robert Vance',
        campName: 'Cardiology Health & Vitality Camp',
        story:
          'During the routine ECG check at CareCamp, doctors detected an early heart blockage. Timely intervention prevented a severe attack.',
        image: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400',
        date: '2026-07-15',
      },
      {
        title: 'Clear Vision Restored',
        patientName: 'Maria Garcia',
        campName: 'Vision & Eye Care Wellness Camp',
        story:
          'I had trouble reading for months due to cataracts. CareCamp provided free screening and arranged affordable corrective surgery.',
        image: 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=400',
        date: '2026-07-20',
      },
      {
        title: 'Healthy Smiles for My Children',
        patientName: 'David & Family',
        campName: 'Pediatric & Dental Care Camp',
        story:
          'CareCamp dentists taught my kids proper brushing techniques and treated early cavities for free.',
        image: 'https://images.unsplash.com/photo-1491438590914-bc09fcaaf77a?w=400',
        date: '2026-07-25',
      },
      {
        title: 'Walking Without Pain Again',
        patientName: 'Eleanor Roosevelt',
        campName: 'Orthopedic Joint Care Camp',
        story:
          'Custom physiotherapy plans and knee braces provided at the camp gave me my mobility back.',
        image: 'https://images.unsplash.com/photo-1566492031773-4f4e44671857?w=400',
        date: '2026-07-28',
      },
      {
        title: 'Managing Diabetes Effortlessly',
        patientName: 'Samuel Jackson',
        campName: 'Diabetes Awareness Camp',
        story:
          'The personalized nutrition chart helped lower my HbA1c levels from 8.5 to 6.2 in three months.',
        image: 'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=400',
        date: '2026-08-01',
      },
      {
        title: 'Skin Cancer Prevented',
        patientName: 'Chloe Bennett',
        campName: 'Dermatology & Skin Camp',
        story:
          'A suspicious mole identified during the skin screening was safely removed before becoming malignant.',
        image: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=400',
        date: '2026-08-03',
      },
      {
        title: 'Hearing My Grandchildren Clear Again',
        patientName: 'Arthur Pendelton',
        campName: 'ENT & Hearing Care Camp',
        story:
          'Free audiology testing and subsidized hearing aid fitting transformed my daily life.',
        image: 'https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=400',
        date: '2026-08-05',
      },
      {
        title: 'Peace of Mind for Mothers',
        patientName: 'Sophia Lin',
        campName: 'Women Wellness Camp',
        story:
          'Comprehensive gynecological checkups provided immense relief and health education for mothers.',
        image: 'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=400',
        date: '2026-08-07',
      },
      {
        title: 'Recovery from Chronic Migraines',
        patientName: 'Daniel Craig',
        campName: 'Neurology Checkup Camp',
        story:
          'Neurologist consultations at CareCamp identified sleep apnoea as the root cause of my severe headaches.',
        image: 'https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?w=400',
        date: '2026-08-08',
      },
      {
        title: 'Community Health Awareness Boost',
        patientName: 'Linda Thompson',
        campName: 'General Health & Vitality Camp',
        story:
          'CareCamp brought essential healthcare right to our rural neighborhood where hospital access is limited.',
        image: 'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=400',
        date: '2026-08-10',
      },
    ];

    const seededSuccessStories = await SuccessStory.insertMany(successStoriesData);
    console.log(`Seeded ${seededSuccessStories.length} Success Stories.`);

    // -------------------------------------------------------------
    // 8. SEED FAQS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding FAQs...');
    await Faq.deleteMany({});

    const faqsData = [
      {
        question: 'How do I register for a medical camp?',
        answer:
          'Browse available camps on the homepage, click "Register Now", fill in participant details, and confirm registration.',
        category: 'Registration',
      },
      {
        question: 'Are camp registration fees refundable?',
        answer:
          'Refund requests submitted at least 48 hours prior to the camp start date are processed in full.',
        category: 'Payments',
      },
      {
        question: 'What documents should I bring to the camp?',
        answer:
          'Please bring a valid photo ID, your registration confirmation ticket, and any previous medical records.',
        category: 'General',
      },
      {
        question: 'Can I register on behalf of a family member?',
        answer:
          'Yes, you can register family members by providing their details during the registration process.',
        category: 'Registration',
      },
      {
        question: 'How do organizers post new medical camps?',
        answer:
          'Registered organizers can navigate to the Organizer Dashboard and click "Add Camp" to post camp details.',
        category: 'Organizer',
      },
      {
        question: 'What payment methods are supported for paid camps?',
        answer: 'We support all major credit/debit cards via secure Stripe payment integration.',
        category: 'Payments',
      },
      {
        question: 'Will I receive a medical summary report after the camp?',
        answer:
          'Yes, attending doctors provide digital summary reports uploaded directly to your participant profile.',
        category: 'Medical Reports',
      },
      {
        question: 'How can I submit feedback after attending a camp?',
        answer:
          'Go to your Registered Camps page and click "Feedback" to rate and review your experience.',
        category: 'Feedback',
      },
      {
        question: 'Are free camps completely free of charge?',
        answer:
          'Yes, free camps require zero fee payment for consultations and basic screening tests.',
        category: 'General',
      },
      {
        question: 'How do I cancel my registration if I cannot attend?',
        answer:
          'Go to your Registered Camps dashboard and click "Cancel Registration" before the camp start date.',
        category: 'Registration',
      },
    ];

    const seededFaqs = await Faq.insertMany(faqsData);
    console.log(`Seeded ${seededFaqs.length} FAQs.`);

    // -------------------------------------------------------------
    // 9. SEED BLOGS (10 Items)
    // -------------------------------------------------------------
    console.log('Seeding Blogs...');
    await Blog.deleteMany({});

    const blogsData = [
      {
        title: '10 Essential Heart Health Tips for Adults Over 40',
        summary:
          'Learn practical daily habits, dietary choices, and exercise routines to keep your heart healthy and resilient.',
        author: 'Dr. Robert Chen',
        category: 'Cardiology',
        image: 'https://images.unsplash.com/photo-1505751172876-fa1923c5c528?w=600',
        readTime: '5 min read',
        createdAt: '2026-08-01',
      },
      {
        title: 'Understanding Eye Strain in the Digital Age',
        summary:
          'Effective strategies to protect your vision and prevent digital eye fatigue when working long hours on screens.',
        author: 'Dr. Emily Vance',
        category: 'Ophthalmology',
        image: 'https://images.unsplash.com/photo-1584515979956-d9f6e5d09982?w=600',
        readTime: '4 min read',
        createdAt: '2026-08-02',
      },
      {
        title: 'Childhood Vaccination Schedule: A Parent Guide',
        summary:
          'A complete guide for parents explaining essential childhood vaccines, timelines, and safety guidelines.',
        author: 'Dr. Maria Rodriguez',
        category: 'Pediatrics',
        image: 'https://images.unsplash.com/photo-1581594693702-fbdc51b2763b?w=600',
        readTime: '6 min read',
        createdAt: '2026-08-03',
      },
      {
        title: 'The Golden Rules of Daily Oral Hygiene',
        summary:
          'Discover how daily flossing, proper brushing techniques, and dental checkups prevent gum disease.',
        author: 'Dr. Alan Harper',
        category: 'Dentistry',
        image: 'https://images.unsplash.com/photo-1606811841689-23dfddce3e95?w=600',
        readTime: '4 min read',
        createdAt: '2026-08-04',
      },
      {
        title: 'Preventing Joint Pain & Arthritis in Active Lifestyles',
        summary:
          'Key joint protection tips, stretching routines, and posture tips to maintain bone and mobility health.',
        author: 'Dr. James Thorne',
        category: 'Orthopedics',
        image: 'https://images.unsplash.com/photo-1579684385127-1ef15d508118?w=600',
        readTime: '5 min read',
        createdAt: '2026-08-05',
      },
      {
        title: 'Demystifying HbA1c: What Your Blood Glucose Means',
        summary:
          'Understand blood sugar metrics and learn proactive steps to manage and prevent Type 2 Diabetes.',
        author: 'Dr. Priya Sharma',
        category: 'Endocrinology',
        image: 'https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?w=600',
        readTime: '7 min read',
        createdAt: '2026-08-06',
      },
      {
        title: 'Sun Protection Essentials for Healthy Skin',
        summary:
          'Dermatologist recommendations on SPF ratings, UV radiation protection, and early skin cancer screening.',
        author: 'Dr. Sophia Martinez',
        category: 'Dermatology',
        image: 'https://images.unsplash.com/photo-1629909613654-28e377c37b09?w=600',
        readTime: '4 min read',
        createdAt: '2026-08-07',
      },
      {
        title: 'Protecting Your Hearing in Loud Environments',
        summary:
          'How ambient noise affects hearing health and practical advice on using noise-canceling protection.',
        author: 'Dr. William Blake',
        category: 'ENT',
        image: 'https://images.unsplash.com/photo-1516549655169-df83a0774514?w=600',
        readTime: '5 min read',
        createdAt: '2026-08-08',
      },
      {
        title: 'Boost Brain Power: Habits for Memory & Focus',
        summary:
          'Neuroscience-backed daily exercises, nutrition, and sleep hygiene practices to sharpen memory retention.',
        author: 'Dr. Arthur Pendelton',
        category: 'Neurology',
        image: 'https://images.unsplash.com/photo-1551076805-e1869033e561?w=600',
        readTime: '6 min read',
        createdAt: '2026-08-09',
      },
      {
        title: 'Why Preventive Medical Checkups Matter Most',
        summary:
          'Why attending annual wellness camps and routine health screenings lead to longer, healthier lives.',
        author: 'Dr. Sarah Connor',
        category: 'General Health',
        image: 'https://images.unsplash.com/photo-1532938911079-1b06ac7ceec7?w=600',
        readTime: '5 min read',
        createdAt: '2026-08-10',
      },
    ];

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
