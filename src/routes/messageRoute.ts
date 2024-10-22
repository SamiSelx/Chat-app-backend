import express from 'express'
import Authorization from '../middlewares/authorization'
import { getMessages, sendMessage,sendMessageRoom,getMessagesRoom } from '../controllers/messagesControllers'
import MessageModel from '../models/message.model'
import ConversationModel from '../models/conversation.model'
import UserModel from '../models/user.model'
import multer from 'multer'
const router = express.Router()


const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, './src/uploads')
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now()
      cb(null, uniqueSuffix + file.originalname)
    }
})
const upload = multer({storage:storage})

router.post('/send/:recieverId',Authorization,upload.single('file'),sendMessage)
router.get('/:recieverId',Authorization,getMessages)
router.post('/send/room/:roomName',Authorization,upload.single('file'),sendMessageRoom)
router.get('/room/:roomName',Authorization,getMessagesRoom)


router.delete('/',async (req,res)=>{
    await MessageModel.deleteMany({})
    await ConversationModel.deleteMany({})
    await UserModel.deleteMany({})
    res.sendStatus(200)
})

export default router