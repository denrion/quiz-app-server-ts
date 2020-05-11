import { RequestHandler } from 'express';

const setUserIdFromRequest = (fieldName: string): RequestHandler => (
  req,
  res,
  next
) => {
  if (!req.body[fieldName]) req.body[fieldName] = req.user.id;
  next();
};

export default setUserIdFromRequest;
