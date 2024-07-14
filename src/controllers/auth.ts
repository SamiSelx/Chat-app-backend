import { Request,Response, urlencoded } from "express"
import UserModel from "../models/user.model"
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { userValidator } from "../utils/userValidator"
import ResponseI from "../types/response"
import { UserI } from "../types/user"
import nodemailer from 'nodemailer'
import speakeasy from 'speakeasy'


const transporter = nodemailer.createTransport({
    service: "outlook",
    host: "smtp.outlook.com",
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASSWORD,
    },
});
const sendOTP = (email:string) => {
    const secret = speakeasy.generateSecret({ length: 20 });
    const token = speakeasy.totp({
      secret: secret.base32,
      encoding: 'base32'
    });
  
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${token}`
    };
  
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });
  
    return secret.base32;
};

const MAX_LOGIN_ATTEMPTS = 5
const LOCK_TIME = 60 * 1000; // 1min

const incrementLoginAttempts = async (user:any) => {
    if (user.loginUntil && user.loginUntil > Date.now()) {
      return;
    }
  
    user.loginAttempts += 1;
  
    if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
      user.loginUntil = Date.now() + LOCK_TIME;
      user.loginAttempts = 0
    }
  
    await user.save();
};


const resetLoginAttempts = async (user:any) => {
    user.loginAttempts = 0;
    user.loginUntil = undefined;
    await user.save();
};

export const login = async (req:Request,res:Response)=>{
    const {email,password} = req.body

    try {
        const user = await UserModel.findOne({email})
        if(!user){
            res.status(400).json({status:'failed',message:'email invalid'})
            return
        }

        // Check if user is blocked
        if(user.loginUntil && user.loginUntil > Date.now()){
            res.status(400).json({status:'failed',message:'Account is locked. Please try again later.'})
            return
        }


        const isMatch  = await bcrypt.compare(password,user.password)
        if(!isMatch){
            // if password incorrect inrement login attempts
            await incrementLoginAttempts(user)
            res.status(400).json({status:'failed',message:'password invalid'})
            return
        }

        await resetLoginAttempts(user)

        const secret = sendOTP(user.email)
        user.tempSecret = secret
        await user.save()

        // const token = jwt.sign({_id:user._id},process.env.SECRET_KEY!)
        // const userLogin = {
        //     id:user._id.toString(),
        //     username:user.username,
        //     email:user.email,
        //     room:user.room,
        //     token
        // }
        // const response:ResponseI = {status:'success',message:'login successfully',data:userLogin}
        const response:ResponseI = {status:'success',message:'OTP sent to your email. Please verify.'}
        res.status(200).json(response)
   
    } catch (error) {
        console.log(error);
        const response:ResponseI = {status:'failed',message:'error'}
        res.status(400).json(response)
        return
    }

}

export const verifyOtp = async (req:Request,res:Response)=>{
    const {email,code} = req.body
    console.log("verify req",req.body);
    
    const user = await UserModel.findOne({email})
    console.log('user is ',user);
    
    if(!user){
        res.status(400).json({status:'failed',message:'email incorrect'})
        return
    }
    console.log('code' , code);
    console.log('secret is ',user.tempSecret);
    
    const verified = speakeasy.totp.verify({
      secret: user.tempSecret!,
      encoding: 'base32',
      token: code,
      window: 3
    });
    console.log('after verified',verified);
    

    if (verified) {
        user.tempSecret = undefined;
        await user.save();
        const token = jwt.sign({_id:user._id},process.env.SECRET_KEY!)
        const userLogin = {
            id:user._id.toString(),
            username:user.username,
            email:user.email,
            room:user.room,
            token
        }
        const response:ResponseI = {status:'success',message:'login successfully',data:userLogin}
        res.status(200).json(response)
      } else {
        res.status(400).json({status:'failed',message:'invalid OTP'})
      }

}

export const register = async (req:Request,res:Response)=>{
    const {username,email,password} = req.body
    if(!username || !email || !password){
        res.status(400).json({status:'failed',message:'u must fill all the field'})
        return
    }

    const exist = await UserModel.findOne({email})
    if(exist){
        res.status(400).json({status:'failed',message:'email already used'})
        return
    }

    const {error} = userValidator.validate({username,email,password})
    console.log(error);
    
    if(error){
        res.status(400).json({status:'failed',message:error.details[0].message})
        return
    }
    
    try {
        const saltRound = 10
        const salt = await bcrypt.genSalt(saltRound)
        const passwordHash = await bcrypt.hash(password,salt)
        const userCreated = await UserModel.create({username,email,password:passwordHash})
        const token = jwt.sign({_id:userCreated._id},process.env.SECRET_KEY!)
        const userRegistred = {
            id:userCreated._id.toString(),
            username:userCreated.username,
            email:userCreated.email,
            room:userCreated.room,
            token
        }
        res.status(201).json({status:'success',message:'User Created Successfully',data:userRegistred})

    } catch (error) {
        console.log(error);
        res.status(400).json({status:'failed',message:'Creation failed'})
    }

}
