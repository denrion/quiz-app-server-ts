import { CookieOptions, Response } from 'express';
import status from 'http-status';
import ResponseStatus from '../@types/ResponseStatus';
import { JWT_COOKIE_EXPIRES_IN } from '../config/constants';
import User, { UserDoc, UserProps } from '../models/User';
import catchAsync from '../utils/catchAsync';
import BadRequestError from '../utils/errors/BadRequestError';
import UnauthorizedError from '../utils/errors/UnauthorizedError';

/**
 * @desc      Get Current Logged In user
 * @route     GET /api/v1/auth/me
 * @access    Private
 */
export const getMe = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  res.status(status.OK).json({
    success: ResponseStatus.SUCCESS,
    data: { user },
  });
});

/**
 * @desc      Signup user
 * @route     POST /api/v1/auth/signup
 * @access    Public
 */
export const signup = catchAsync(async (req, res, next) => {
  const { role, ...userFields } = req.body as UserProps;

  const newUser = await User.create(userFields);

  createAndSendToken(newUser, status.CREATED, res);
});

/**
 * @desc      Login user
 * @route     POST /api/v1/auth/login
 * @access    Public
 */
export const login = catchAsync(async (req, res, next) => {
  const { username, password } = req.body as LoginCredentials;

  if (!username || !password)
    return next(new BadRequestError('Please provide username and password!'));

  const user = await User.findByUsername(username).select('+password');

  if (!user || !(await user.isCorrectPassword(password, user.password)))
    return next(new UnauthorizedError('Invalid credentials'));

  createAndSendToken(user, status.OK, res);
});

const createAndSendToken = (
  user: UserDoc,
  statusCode: number,
  res: Response
) => {
  const token = user.signToken();

  const cookieOptions: CookieOptions = {
    expires: new Date(
      Date.now() + JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000 // turn into milis
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.status(statusCode).cookie('jwt', token, cookieOptions).json({
    status: ResponseStatus.SUCCESS,
    data: { token, user },
  });
};

interface LoginCredentials {
  username: string;
  password: string;
}
