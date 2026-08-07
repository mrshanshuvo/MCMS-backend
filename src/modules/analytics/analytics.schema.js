const { z } = require('zod');

const exportQuerySchema = {
  query: z.object({
    campId: z.string().optional(),
    format: z.enum(['csv']).optional(),
  }),
};

module.exports = {
  exportQuerySchema,
};
