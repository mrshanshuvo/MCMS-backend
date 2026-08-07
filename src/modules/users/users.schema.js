const { z } = require('zod');

const emailSchema = z.string().email({ message: 'Invalid email address' });

const upsertUserSchema = {
  body: z.object({
    email: emailSchema,
    name: z.string().optional(),
    photoURL: z.string().optional(),
    created_at: z.string().optional(),
    last_login: z.string().optional(),
  }),
};

const updateUserSchema = {
  params: z.object({
    email: emailSchema,
  }),
  body: z.object({
    name: z.string().optional(),
    photoURL: z.string().optional(),
    phone: z.string().optional(),
    address: z.string().optional(),
  }),
};

const emailParamSchema = {
  params: z.object({
    email: emailSchema,
  }),
};

module.exports = {
  upsertUserSchema,
  updateUserSchema,
  emailParamSchema,
};
