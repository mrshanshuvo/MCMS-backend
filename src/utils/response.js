const sendResponse = (res, statusCode, { success, data, message, meta }) => {
  const responseBody = {
    success,
    ...(message && { message }),
    ...(data !== undefined && { data }),
    ...(meta && { meta }),
  };
  return res.status(statusCode).json(responseBody);
};

module.exports = sendResponse;
