import { Schema,model } from "mongoose";


const ConversationSchema = new Schema({
    message:{
        type:String,
        required:true
    },
    author:{
        type:String,
        required:true
    },
    author_id:{
        type:String,
        required:true
    }
},{
    _id:false
})

const RoomSchema1 = new Schema({
    roomName:{
        type:String,
        unique:true,
    },
    conversation:[{
        type:ConversationSchema,
        required:true
    }],
    users:[{
        type:Schema.Types.ObjectId,
        ref:'User'
    }]
})

const RoomModel1 = model('Room1',RoomSchema1)

export default RoomModel1