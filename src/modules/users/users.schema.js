const { z } = require('zod');

const idOrEmailSchema = z.string().min(1, 'User ID or Email is required');

const upsertUserSchema = {
  body: z.object({
    email: z.email({ message: 'Invalid email address' }),
    name: z.string().optional(),
    photoURL: z.string().optional(),
    created_at: z.string().optional(),
    last_login: z.string().optional(),
  }),
};

const updateUserSchema = {
  params: z.object({
    id: idOrEmailSchema.optional(),
    email: idOrEmailSchema.optional(),
  }),
  body: z.object({
    name: z.string().optional(),
    photoURL: z.string().optional(),
    phone: z.string().optional(),
    address: z.string().optional(),
  }),
};

const userParamSchema = {
  params: z.object({
    id: idOrEmailSchema.optional(),
    email: idOrEmailSchema.optional(),
  }),
};

const updateRoleSchema = {
  params: z.object({
    id: idOrEmailSchema.optional(),
    email: idOrEmailSchema.optional(),
  }),
  body: z.object({
    role: z.enum(['participant', 'organizer'], {
      message: 'Role must be participant or organizer',
    }),
  }),
};

const getAllUsersSchema = {
  query: z.object({
    page: z.string().optional(),
    limit: z.string().optional(),
    search: z.string().optional(),
    role: z.string().optional(),
  }),
};

module.exports = {
  upsertUserSchema,
  updateUserSchema,
  userParamSchema,
  emailParamSchema: userParamSchema,
  updateRoleSchema,
  getAllUsersSchema,
};
