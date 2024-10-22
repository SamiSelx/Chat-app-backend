import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import RoomModel from "../models/room.modelv2";
import UserModel from "../models/user.model";

export const app = express();
export const httpServer = createServer(app);

export const io = new Server(httpServer, {
  cors: {
    origin: process.env.FRONT_URL!
  },
});

type UserSockets = { id: string; socketId: string }[];


let onlineUser:UserSockets = []

io.on("connection", async (socket) => {
  console.log("User Connected ", socket.id);
  socket.on("join-room", (rooms:string[]) => {
    console.log('rooms',rooms);
    rooms.forEach((room)=>{
        socket.join(room);
    })
  });
  socket.on("test", (msg) => {
    console.log(msg);
    // send to everyone + to the same socket use io.emit()
    // send to everyone + not to myself use socket.brodcast.emit()
    // send to everyone on the room + not myself (brodcast) use socket.to().emit()
    // send just to the same socket (response) use socket.emit()
    io.emit("test-server", msg);
  });

  socket.on("addOnlineUser", (userId) => {
    const exist = onlineUser?.find((user) => user.id == userId);
    if (!exist) onlineUser?.push({ id: userId, socketId: socket.id });
    io.emit("getOnlineUsers", onlineUser);
    console.log("userId", userId, onlineUser);
  });

  socket.on("message-dm", (message) => {
    console.log("dm messg: ", message);
    
    socket.to(message.recieverId).emit("recieve-message", message);
    // io.emit('recieve-message',message)
  });

  socket.on("message", async (message) => {
    console.log(message, "from ", socket.id);
    // socket.emit('recieved-message',msg + ' from server')
    const message_info = {
      message: message.message,
      author: message.author,
      author_id: message.author_id,
    };
    const exist = await RoomModel.findOne({ roomName: message.room });
    const conversation = exist?.conversation;
    console.log("array : ", conversation);
    !exist
      ? await RoomModel.create({
          roomName: message.room,
          conversation: [{ ...message_info }],
        })
      : await RoomModel.updateMany(
          { roomName: message.room },
          { $push: { conversation: { ...message_info } } }
        );
    message.room === ""
      ? socket.broadcast.emit("recieved-message", message_info)
      : socket.to(message.room).emit("recieved-message", message_info);
  });

  // setInterval(()=>socket.emit('recieved-message',messages),1000)
  // socket.emit('recieved-message',messages)
  socket.on("disconnect", async (reason) => {
    console.log("User Disconnected ", socket.id, reason);
    onlineUser = onlineUser?.filter((user) => user.socketId !== socket.id);
    io.emit("getOnlineUsers", onlineUser);

    // Second method using DB
    // const userId = userSocket.get(socket.id)
    // if(userId){
    //   await UserModel.updateOne({_id:userId},{isOnline:false})
    //   userSocket.delete(socket.id)
    //   console.log('user is offline',userId);
    //   socket.broadcast.emit('status-user',{id:userId,isOnline:false})

    // }
  });
});
