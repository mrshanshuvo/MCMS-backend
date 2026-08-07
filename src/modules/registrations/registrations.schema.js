const { z } = require('zod');

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const objectIdSchema = z.string().regex(objectIdRegex, 'Invalid ObjectId format');

const registerCampSchema = {
  body: z.object({
    campId: objectIdSchema,
    participantName: z.string().optional(),
    participantEmail: z.email({ message: 'Invalid email address' }),
    age: z.union([z.number().positive(), z.string().regex(/^\d+$/).transform(Number)]),
    phoneNumber: z.string().min(1, 'Phone number is required'),
    gender: z.string().min(1, 'Gender is required'),
    emergencyContact: z.string().min(1, 'Emergency contact is required'),
  }),
};

const checkRegistrationSchema = {
  query: z.object({
    campId: objectIdSchema,
  }),
};

const idParamSchema = {
  params: z.object({
    id: objectIdSchema,
  }),
};

const campIdParamSchema = {
  params: z.object({
    campId: objectIdSchema,
  }),
};

module.exports = {
  registerCampSchema,
  checkRegistrationSchema,
  idParamSchema,
  campIdParamSchema,
};
