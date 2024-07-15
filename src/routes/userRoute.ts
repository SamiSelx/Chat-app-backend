import express from 'express'
import {login,register, verifyOtp} from '../controllers/auth'
import { getAllUsers, getUser, updateUser } from '../controllers/userControllers'
import Authorization from '../middlewares/authorization'
import rateLimit from 'express-rate-limit'

const router = express.Router()

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10000, // limit each IP to 100 requests per windowMs
    message: "Too many requests, please try again later."
  });

router.post('/register',register)

router.post('/login',limiter,login)
router.post('/verifyOtp',verifyOtp)
router.get('/',Authorization,getAllUsers)

router.get('/me',Authorization,getUser)

router.patch('/me',Authorization,updateUser)

export default router