const { z } = require('zod');

const upsertUserSchema = {
  body: z.object({
    email: z.string().email('Invalid email address'),
    name: z.string().optional(),
    photoURL: z.string().optional(),
    created_at: z.string().optional(),
    last_login: z.string().optional(),
  }),
};

const updateUserSchema = {
  params: z.object({
    email: z.string().email('Invalid email address'),
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
    email: z.string().email('Invalid email address'),
  }),
};

module.exports = {
  upsertUserSchema,
  updateUserSchema,
  emailParamSchema,
};
