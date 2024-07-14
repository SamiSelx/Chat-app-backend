import {Schema, model} from 'mongoose'
import { UserI } from '../types/user'

const UserSchema = new Schema({
    username:{
        type:String,
        required:true
    },
    email:{
        type:String,
        unique:true,
        required:true
    },
    password:{
        type:String,
        required:true
    },
    room:[{
        type:String,
        ref:"Room"
    }],
    loginAttempts:{
        type:Number,
        default:0
    },
    loginUntil:Number,
    tempSecret:String
})

const UserModel = model<UserI>('User',UserSchema)

export default UserModel