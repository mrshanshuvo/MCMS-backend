const { z } = require('zod');

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const objectIdSchema = z.string().regex(objectIdRegex, 'Invalid ObjectId format');

const createCampSchema = {
  body: z.object({
    name: z.string().min(1, 'Camp name is required'),
    location: z.string().min(1, 'Location is required'),
    fees: z.number().min(0, 'Fees must be a positive number'),
    dateTime: z.string().min(1, 'Date and time is required'),
    healthcareProfessional: z.string().min(1, 'Healthcare professional is required'),
    description: z.string().optional(),
    image: z.string().optional(),
  }),
};

const updateCampSchema = {
  params: z.object({
    campId: objectIdSchema,
  }),
  body: z.object({
    name: z.string().optional(),
    location: z.string().optional(),
    fees: z.number().min(0).optional(),
    dateTime: z.string().optional(),
    healthcareProfessional: z.string().optional(),
    description: z.string().optional(),
    image: z.string().optional(),
    imageURL: z.string().optional(),
  }),
};

const campIdParamSchema = {
  params: z.object({
    campId: objectIdSchema,
  }),
};

const idParamSchema = {
  params: z.object({
    id: objectIdSchema,
  }),
};

module.exports = {
  createCampSchema,
  updateCampSchema,
  campIdParamSchema,
  idParamSchema,
};
