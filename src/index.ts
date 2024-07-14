import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import './configs/connectDB'

// Routes
import userRouter from './routes/userRoute'
import messageRoute from './routes/messageRoute'
import roomRouter from './routes/roomRoute'
// Socket config
import {app,httpServer} from './socket/socket'
import path from 'path'
const port = process.env.PORT
import { graphqlHTTP } from 'express-graphql'
import schema from './Schemas/index'

app.use('/graphql',graphqlHTTP({
    schema,
    graphiql:true
}))

app.use(cors())

app.use('/uploads',express.static(path.join(__dirname,'/uploads')))
// Perse Form
app.use(express.urlencoded({extended:true}))
// Perse json
app.use(express.json())

app.use('/api/user',userRouter)
app.use('/api/room',roomRouter)
app.use('/api/message',messageRoute)

httpServer.listen(port,()=>{
    console.log(`Server Started on port ${port}`);
})
