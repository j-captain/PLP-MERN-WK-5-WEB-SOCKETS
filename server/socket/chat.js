const Message = require('../models/Message');
const Room = require('../models/Room');
const User = require('../models/User');

module.exports = (io, socket) => {
  // Join a room (public or private)
  const joinRoom = async (roomId) => {
    try {
      // Verify user has access to the room
      const room = await Room.findById(roomId);
      if (!room) {
        return socket.emit('error', { message: 'Room not found' });
      }

      if (room.isPrivate && !room.participants.includes(socket.user._id)) {
        return socket.emit('error', { message: 'Access denied to private room' });
      }

      socket.join(roomId);
      
      // Update user's current room
      await User.findByIdAndUpdate(socket.user._id, { currentRoom: roomId });

      // Get last 50 messages
      const messages = await Message.find({ room: roomId })
        .sort({ createdAt: -1 })
        .limit(50)
        .populate('sender', 'username')
        .populate('readBy', 'username');

      socket.emit('previous_messages', messages.reverse());
      
      // Notify others in the room
      socket.to(roomId).emit('user_joined', {
        userId: socket.user._id,
        username: socket.user.username
      });
      
    } catch (error) {
      console.error('Join room error:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  };

  // Send a message to a room
  const sendMessage = async (payload) => {
    try {
      const newMessage = new Message({
        content: payload.content,
        sender: socket.user._id,
        room: payload.roomId,
        isFile: payload.isFile || false,
        fileName: payload.fileName,
        fileType: payload.fileType
      });
      
      await newMessage.save();
      
      const messageWithSender = {
        ...newMessage.toObject(),
        sender: { _id: socket.user._id, username: socket.user.username },
        readBy: [] // Initialize readBy array
      };

      io.to(payload.roomId).emit('new_message', messageWithSender);
      
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  };

  // Typing indicator
  const typing = (roomId) => {
    socket.to(roomId).emit('typing', {
      userId: socket.user._id,
      username: socket.user.username
    });
  };

  // Mark message as read
  const markAsRead = async (messageId) => {
    try {
      const updatedMessage = await Message.findOneAndUpdate(
        { _id: messageId, readBy: { $ne: socket.user._id } },
        { $push: { readBy: socket.user._id } },
        { new: true }
      ).populate('readBy', 'username');
      
      if (updatedMessage) {
        io.to(updatedMessage.room.toString()).emit('message_read', {
          messageId: updatedMessage._id,
          readBy: updatedMessage.readBy
        });
      }
    } catch (error) {
      console.error('Mark as read error:', error);
    }
  };

  // Start a private chat
  const startPrivateChat = async ({ receiverId }) => {
    try {
      // Validate receiver exists
      const receiver = await User.findById(receiverId);
      if (!receiver) {
        return socket.emit('error', { message: 'User not found' });
      }

      // Create consistent room name regardless of who initiates
      const participants = [socket.user._id, receiverId].sort();
      const roomName = participants.join('-');
      
      // Find or create room
      let room = await Room.findOne({ name: roomName });
      
      if (!room) {
        room = new Room({
          name: roomName,
          isPrivate: true,
          participants: participants,
          createdBy: socket.user._id
        });
        await room.save();
        
        // Notify both users about the new private chat
        io.to(socket.user._id.toString()).emit('private_room_created', room);
        io.to(receiverId.toString()).emit('private_room_created', room);
      }
      
      // Join the room
      socket.join(room._id);
      
      // Return room info to the initiating user
      socket.emit('private_room_ready', {
        roomId: room._id,
        receiver: {
          _id: receiver._id,
          username: receiver.username
        }
      });
      
    } catch (error) {
      console.error('Private chat error:', error);
      socket.emit('error', { message: 'Failed to start private chat' });
    }
  };

  // User disconnects
  const handleDisconnect = async () => {
    try {
      // Update user status and notify
      await User.findByIdAndUpdate(socket.user._id, { 
        online: false,
        lastSeen: new Date() 
      });
      
      // Notify all rooms the user was in
      socket.rooms.forEach(roomId => {
        if (roomId !== socket.id) { // Skip the default room
          socket.to(roomId).emit('user_left', {
            userId: socket.user._id,
            username: socket.user.username
          });
        }
      });
    } catch (error) {
      console.error('Disconnect handler error:', error);
    }
  };

  // Socket event listeners
  socket.on('join_room', joinRoom);
  socket.on('send_message', sendMessage);
  socket.on('typing', typing);
  socket.on('mark_as_read', markAsRead);
  socket.on('start_private_chat', startPrivateChat);
  socket.on('disconnect', handleDisconnect);
};