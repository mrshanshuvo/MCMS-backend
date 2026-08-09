const authService = require('./auth.service');
const sendResponse = require('../../utils/response');

const register = async (req, res, next) => {
  try {
    const result = await authService.registerUserInDB(req.body);

    if (result.duplicate) {
      return sendResponse(res, 400, {
        success: false,
        message: 'User with this email already exists',
      });
    }

    return sendResponse(res, 201, {
      success: true,
      message: 'User registered successfully',
      data: {
        token: result.token,
        user: result.user,
      },
    });
  } catch (error) {
    next(error);
  }
};

const login = async (req, res, next) => {
  try {
    const result = await authService.loginUserInDB(req.body);

    if (result.invalidCredentials) {
      return sendResponse(res, 401, {
        success: false,
        message: 'Invalid email or password',
      });
    }

    if (result.socialUser) {
      return sendResponse(res, 400, {
        success: false,
        message: 'This account was created via social login. Please use Google/Facebook login.',
      });
    }

    return sendResponse(res, 200, {
      success: true,
      message: 'Login successful',
      data: {
        token: result.token,
        user: result.user,
      },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
};
