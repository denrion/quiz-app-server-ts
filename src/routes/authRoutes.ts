import { Router } from 'express';
import { getMe, login, signup } from '../controllers/authController';
import isAuth from '../middleware/isAuth';

const router = Router();

router.get('/me', isAuth, getMe);
router.post('/signup', signup);
router.post('/login', login);

export { router as authRouter };
