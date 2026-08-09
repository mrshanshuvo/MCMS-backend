const { z } = require('zod');

const registerSchema = {
  body: z.object({
    email: z.email({ message: 'Invalid email address' }),
    password: z.string().min(6, 'Password must be at least 6 characters'),
    name: z.string().optional(),
    photoURL: z.string().optional(),
    role: z.enum(['participant', 'organizer']).optional(),
  }),
};

const loginSchema = {
  body: z.object({
    email: z.email({ message: 'Invalid email address' }),
    password: z.string().min(1, 'Password is required'),
  }),
};

module.exports = {
  registerSchema,
  loginSchema,
};
