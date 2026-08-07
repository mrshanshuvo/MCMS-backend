const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { env } = require('./config/env');
const logger = require('./config/logger');
const morganMiddleware = require('./middlewares/morgan.middleware');
const { notFoundHandler, globalErrorHandler } = require('./middlewares/errorHandler');
const paymentsController = require('./modules/payments/payments.controller');

// Feature Routes
const usersRoutes = require('./modules/users/users.routes');
const campsRoutes = require('./modules/camps/camps.routes');
const registrationsRoutes = require('./modules/registrations/registrations.routes');
const paymentsRoutes = require('./modules/payments/payments.routes');
const feedbackRoutes = require('./modules/feedback/feedback.routes');
const publicRoutes = require('./modules/public/public.routes');

const app = express();

// Security, CORS, and Morgan HTTP Logging Middlewares
app.use(
  cors({
    origin:
      env.NODE_ENV === 'production'
        ? ['https://mcms-auth.web.app']
        : ['https://mcms-auth.web.app', 'http://localhost:5173'],
    credentials: true,
  })
);
app.use(helmet());
app.use(morganMiddleware);
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  })
);

// Raw Body Route for Stripe Webhooks BEFORE express.json()
app.post(
  '/stripe-webhook',
  express.raw({ type: 'application/json' }),
  paymentsController.stripeWebhook
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

logger.info('Express application initialized with security & logging middlewares.');

module.exports = app;
