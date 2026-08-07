const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { notFoundHandler, globalErrorHandler } = require('./middlewares/errorHandler');

// Feature Routes
const usersRoutes = require('./modules/users/users.routes');
const campsRoutes = require('./modules/camps/camps.routes');
const registrationsRoutes = require('./modules/registrations/registrations.routes');
const paymentsRoutes = require('./modules/payments/payments.routes');
const feedbackRoutes = require('./modules/feedback/feedback.routes');
const publicRoutes = require('./modules/public/public.routes');

const app = express();

// Security and CORS Middlewares
app.use(
  cors({
    origin: ['https://mcms-auth.web.app', 'http://localhost:5173'],
    credentials: true,
  })
);
app.use(helmet());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  })
);

// Body Parser Middleware
app.use(express.json());

// Root Health Check Route
app.get('/', (req, res) => {
  res.send('Medical Camp Management System Backend is Running');
});

// Mount Domain Feature Routes
app.use('/users', usersRoutes);
app.use('/', campsRoutes);
app.use('/', registrationsRoutes);
app.use('/', paymentsRoutes);
app.use('/', feedbackRoutes);
app.use('/', publicRoutes);

// Error Handling Middlewares
app.use(notFoundHandler);
app.use(globalErrorHandler);

module.exports = app;
