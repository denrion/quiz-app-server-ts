import { RequestHandler } from 'express';

const filterByUserId = (fieldName: string): RequestHandler => (
  req,
  res,
  next
) => {
  req.conditions = { [fieldName]: req.user.id };
  next();
};

export default filterByUserId;
