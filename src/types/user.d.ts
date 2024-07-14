export interface UserI{
    _id:string;
    username:string;
    email:string;
    password:string;
    room:string[]
    loginAttempts:number;
    loginUntil?:number;
    tempSecret?:string
}