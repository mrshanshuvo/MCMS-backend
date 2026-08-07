const sendResponse = require('../utils/response');

const validate = (schema) => async (req, res, next) => {
  try {
    if (schema.body) {
      req.body = await schema.body.parseAsync(req.body);
    }
    if (schema.query) {
      req.query = await schema.query.parseAsync(req.query);
    }
    if (schema.params) {
      req.params = await schema.params.parseAsync(req.params);
    }
    next();
  } catch (error) {
    if (error.issues) {
      const formattedErrors = error.issues.map((err) => ({
        field: err.path.join('.'),
        message: err.message,
      }));
      return sendResponse(res, 400, {
        success: false,
        message: 'Validation failed',
        data: formattedErrors,
      });
    }
    next(error);
  }
};

module.exports = validate;
