// seed.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Define models - adjust paths as needed
const User = require('./models/User');
const Room = require('./models/Room');
const Message = require('./models/Message');

// Kenyan names data - MUST INCLUDE THESE ARRAYS
const kenyanFirstNames = [
  'Wanjiru', 'Kamau', 'Nyambura', 'Kipchoge', 'Auma', 'Ochieng', 'Atieno', 
  'Mumbi', 'Korir', 'Chebet', 'Maina', 'Akinyi', 'Odhiambo', 'Wairimu', 'Jelimo'
];

const kenyanLastNames = [
  'Omondi', 'Wambui', 'Kiptoo', 'Onyango', 'Aketch', 'Kariuki', 'Njoroge',
  'Muthoni', 'Kibet', 'Chepkoech', 'Otieno', 'Nyaga', 'Wafula', 'Njeri', 'Koech'
];

const sampleMessages = [
  "Hello everyone, how are you doing today?",
  "I was thinking about our discussion yesterday and had some new ideas",
  "Has anyone seen the latest developments on this topic?",
  "Let's schedule a meeting to discuss this further",
  "I've attached the document we were talking about",
  "What are your thoughts on this approach?",
  "That's an interesting perspective, I hadn't considered that",
  "Could you clarify that last point for me?",
  "I completely agree with what you're saying",
  "Let me research that and get back to you",
  "Here's a link to the article I mentioned earlier",
  "We should definitely explore this further",
  "Has anyone had experience with this before?",
  "I think we're making good progress on this",
  "Let's break this down into smaller tasks"
];

console.log();
console.log('🌱 Starting database seeding...');

// MongoDB connection with error handling
const connectDB = async () => {
  try {
    await mongoose.connect('mongodb://localhost:27017/socketioChat', {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    });
    console.log();
    console.log('🟢 Connected to MongoDB');
  } catch (err) {
    console.error('🔴 MongoDB connection error:', err.message);
    process.exit(1);
  }
};

const seedDatabase = async () => {
  try {
    await connectDB();

    // Clear existing data
    await User.deleteMany({});
    await Room.deleteMany({});
    await Message.deleteMany({});

    // Create users with delays
    const users = [];
    const rawCredentials = [];
    
    console.log('👤 Creating 15 users...');
    console.log();
    for (let i = 0; i < 15; i++) {
      try {
        const firstName = kenyanFirstNames[i];
        const lastName = kenyanLastNames[i];
        const username = `${firstName.toLowerCase()}_${lastName.toLowerCase()}`;
        const password = Math.random().toString(36).slice(-8);

        const user = new User({ 
          username, 
          password
        });
        
        await user.save();
        
        users.push(user);
        rawCredentials.push({ username, password, name: `${firstName} ${lastName}` });
        console.log(`➕ Created user ${username}`);
        
        // Add 500ms delay between creations
        if (i < 14) await new Promise(resolve => setTimeout(resolve, 500));
      } catch (error) {
        console.error(`⚠️ Error creating user ${i+1}:`, error.message);
      }
    }

    // Create only the 5 specific rooms
    const roomNames = ['general', 'arsenal', 'man-u', 'liverpool', 'bedsa'];
    const roomTopics = [
      'General Chat',
      'Arsenal FC Discussions',
      'Manchester United FC',
      'Liverpool FC Fan Club',
      'BEDSA Community'
    ];
    
    const rooms = [];
    console.log('\n🚪 Creating 5 specific rooms...');
    console.log();
    
    for (let i = 0; i < 5; i++) {
      try {
        const creator = users[i];
        const participants = [creator._id];
        
        // Add 2-4 random participants
        const numParticipants = Math.floor(Math.random() * 3) + 2;
        const otherUsers = users.filter(u => u._id.toString() !== creator._id.toString());
        for (let j = 0; j < numParticipants; j++) {
          if (otherUsers.length > 0) {
            const randomIndex = Math.floor(Math.random() * otherUsers.length);
            participants.push(otherUsers[randomIndex]._id);
            otherUsers.splice(randomIndex, 1);
          }
        }

        const room = new Room({
          name: roomNames[i],
          isPrivate: false,
          participants,
          createdBy: creator._id,
          topic: roomTopics[i]
        });
        
        await room.save();
        rooms.push(room);
        console.log(`➕ Created room ${roomNames[i]} (${roomTopics[i]})`);
        
        // Add 500ms delay between creations
        if (i < 4) await new Promise(resolve => setTimeout(resolve, 500));
      } catch (error) {
        console.error(`⚠️ Error creating room ${roomNames[i]}:`, error.message);
      }
    }

    // Create 3 messages for each room
    console.log('\n💬 Creating 3 messages for each room...');
    console.log();
    for (const room of rooms) {
      try {
        const roomParticipants = room.participants;
        
        for (let i = 0; i < 3; i++) {
          const senderIndex = Math.floor(Math.random() * roomParticipants.length);
          const sender = roomParticipants[senderIndex];
          const senderUser = users.find(u => u._id.equals(sender));
          const messageIndex = Math.floor(Math.random() * sampleMessages.length);
          const content = sampleMessages[messageIndex];
          
          const message = new Message({
            content,
            username: senderUser.username,
            room: room._id,
            isFile: false,
            fileName: null,
            fileType: null,
            readBy: [sender]
          });

          await message.save();
          console.log(`   ➕ Added message to room ${room.name} from ${senderUser.username}`);
          
          // Small delay between messages
          if (i < 2) await new Promise(resolve => setTimeout(resolve, 200));
        }
      } catch (error) {
        console.error(`⚠️ Error creating messages for room ${room.name}:`, error.message);
      }
    }

    console.log('\n✅ Seeding completed successfully!');
    console.log();
    console.log('📋 User credentials (pre-hash):');
    console.table(rawCredentials);

    console.log('\n💾 Database Summary:');
    console.log(`   👤 Users created: ${users.length}`);
    console.log(`   🚪 Rooms created: ${rooms.length}`);
    console.log(`   ✉️ Messages created: ${rooms.length * 3}`);
    console.log();

  } catch (error) {
    console.error('\n❌ Seeding failed:', error.message);
  } finally {
    await mongoose.disconnect();
    console.log();
    console.log('🔌 Disconnected from MongoDB');
    process.exit(0);
  }
};

seedDatabase();