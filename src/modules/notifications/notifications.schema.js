const { z } = require('zod');

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const objectIdSchema = z.string().regex(objectIdRegex, 'Invalid ObjectId format');

const markReadSchema = {
  params: z.object({
    id: objectIdSchema,
  }),
};

const getNotificationsSchema = {
  query: z.object({
    page: z.string().optional(),
    limit: z.string().optional(),
    unreadOnly: z.string().optional(),
  }),
};

module.exports = {
  markReadSchema,
  getNotificationsSchema,
};
