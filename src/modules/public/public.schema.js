const { z } = require('zod');

const contactMessageSchema = {
  body: z.object({
    name: z.string().min(1, 'Name is required'),
    email: z.email({ message: 'Invalid email address' }),
    subject: z.string().min(1, 'Subject is required'),
    message: z.string().min(1, 'Message is required'),
  }),
};

module.exports = {
  contactMessageSchema,
};
