const { z } = require('zod');

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const objectIdSchema = z.string().regex(objectIdRegex, 'Invalid ObjectId format');

const submitFeedbackSchema = {
  body: z.object({
    campId: objectIdSchema,
    rating: z.number().min(1, 'Rating must be at least 1').max(5, 'Rating must be at most 5'),
    feedback: z.string().min(1, 'Feedback text is required'),
    name: z.string().optional(),
    photoURL: z.string().optional(),
    images: z.array(z.string()).optional(),
  }),
};

module.exports = {
  submitFeedbackSchema,
};
