require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { instrument } = require("@socket.io/admin-ui");
const cors = require('cors');
const bcrypt = require('bcryptjs');
const connectDB = require('./config/db');
const User = require('./models/User');
const Room = require('./models/Room');
const Messsage = require('./models/Message');
const mongoose = require('mongoose');
const socketio = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mime = require('mime-types');

const app = express();
const server = http.createServer(app);

// Configure file storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Serve static files with proper headers
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, path) => {
    // Set proper Content-Type header for files
    res.setHeader('Content-Type', mime.lookup(path));
  }
}));

// Handle file upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      console.log(colorful.error('No file uploaded'));
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }
    
    console.log(colorful.success(`File uploaded: ${req.file.originalname}`));
    console.log(colorful.debug(`File saved at: ${req.file.path}`));
    
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    res.json({
      success: true,
      url: fileUrl,
      name: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype
    });
  } catch (err) {
    console.log(colorful.error(`File upload error: ${err.message}`));
    res.status(500).json({ success: false, error: 'File upload failed' });
  }
});

// Colorful console helpers
const colorful = {
  success: (text) => `\x1b[32m✓ ${text}\x1b[0m`,
  error: (text) => `\x1b[31m✗ ${text}\x1b[0m`,
  info: (text) => `\x1b[36mℹ ${text}\x1b[0m`,
  warn: (text) => `\x1b[33m⚠ ${text}\x1b[0m`,
  debug: (text) => `\x1b[35m⚡ ${text}\x1b[0m`
};

// Track active users and rooms
const activeUsers = new Map();
const roomUsers = new Map();

// Enhanced CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:5173',
      process.env.CLIENT_URL,
      'https://admin.socket.io'
    ].filter(Boolean);
    
    if (!origin || allowedOrigins.includes(origin)) {
      console.log(colorful.success(`Allowed origin: ${origin || 'unknown'}`));
      callback(null, true);
    } else {
      console.log(colorful.error(`Blocked origin: ${origin}`));
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connection attempt tracker
let connectionAttempts = 0;
const trackConnection = (socket, status) => {
  connectionAttempts++;
  const colors = {
    success: '\x1b[42m\x1b[30m',
    failed: '\x1b[41m\x1b[30m',
    pending: '\x1b[43m\x1b[30m',
    reset: '\x1b[0m'
  };
  
  const statusColor = status === 'success' ? colors.success : 
                     status === 'failed' ? colors.failed : colors.pending;
  
  console.log(`
  ${colors.success}┌─────────────────────────────────────┐${colors.reset}
  ${statusColor}│ ${status.toUpperCase().padEnd(33)}│${colors.reset}
  ${colors.success}├─────────────────────────────────────┤${colors.reset}
  │ ${colorful.info(`Attempt: #${connectionAttempts}`)}
  │ ${colorful.info(`Origin: ${socket.handshake.headers.origin}`)}
  │ ${colorful.info(`IP: ${socket.handshake.address}`)}
  │ ${colorful.info(`Socket ID: ${socket.id}`)}
  │ ${colorful.info(`Time: ${new Date().toISOString()}`)}
  ${colors.success}└─────────────────────────────────────┘${colors.reset}
  `);
};

// API Routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log(colorful.debug(`New registration attempt for: ${username}`));

    if (!username || !password) {
      console.log(colorful.error('Registration failed - Missing fields'));
      return res.status(400).json({ 
        success: false,
        error: 'Username and password required' 
      });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log(colorful.error(`Username ${username} already exists`));
      return res.status(409).json({ 
        success: false,
        error: 'Username already exists' 
      });
    }

    const user = new User({ username, password });
    await user.save();
    
    console.log(colorful.success(`New user registered: ${username}`));
    console.log(colorful.debug(`User count: ${await User.countDocuments()}`));
    
    res.status(201).json({ 
      success: true,
      username: user.username
    });
  } catch (err) {
    console.log(colorful.error(`Registration error: ${err.message}`));
    res.status(500).json({ 
      success: false,
      error: err.message 
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(colorful.debug(`Login attempt for: ${username}`));

    if (!username || !password) {
      console.log(colorful.error('Login failed - Missing credentials'));
      return res.status(400).json({ 
        success: false,
        error: 'Username and password required' 
      });
    }

    const user = await User.findOne({ username }).select('+password');
    
    if (!user) {
      console.log(colorful.error(`User ${username} not found`));
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      console.log(colorful.error(`Invalid password for ${username}`));
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    console.log(colorful.success(`User logged in: ${username}`));
    res.json({ 
      success: true,
      username: user.username
    });
  } catch (err) {
    console.log(colorful.error(`Login error: ${err.message}`));
    res.status(500).json({ 
      success: false,
      error: 'Login failed' 
    });
  }
});

// Root route 
app.get('/', (req, res) => {
  const serverStatus = {
    status: 'running',
    time: new Date().toISOString(),
    port: process.env.PORT || 5000,
    clientPort: 5173,
    clientStatus: 'unknown',
    connectionAttempts: connectionAttempts,
    allowedOrigins: corsOptions.origin instanceof Function ? 
      ['http://localhost:5173', process.env.CLIENT_URL, 'https://admin.socket.io'] : 
      corsOptions.origin
  };

  const net = require('net');
  const clientPortChecker = net.createConnection({ port: 5173 }, () => {
    serverStatus.clientStatus = 'accessible';
    clientPortChecker.end();
    sendResponse();
  });

  clientPortChecker.on('error', (err) => {
    serverStatus.clientStatus = 'inaccessible';
    serverStatus.clientError = err.message;
    sendResponse();
  });

  function sendResponse() {
    const statusIcon = serverStatus.clientStatus === 'accessible' ? '✅' : '❌';
    
    console.log(`
    \x1b[46m\x1b[30m┌─────────────────────────────────────┐\x1b[0m
    \x1b[46m\x1b[30m│ 🏰 SERVER STATUS REPORT              │\x1b[0m
    \x1b[46m\x1b[30m├─────────────────────────────────────┤\x1b[0m
    │ ${colorful.info(`Port: ${serverStatus.port}`)}
    │ ${colorful.info(`Client Port 5173: ${statusIcon} ${serverStatus.clientStatus}`)}
    ${serverStatus.clientError ? `│ ${colorful.error(serverStatus.clientError)}\n` : ''}
    │ ${colorful.info(`Connection Attempts: ${serverStatus.connectionAttempts}`)}
    \x1b[46m\x1b[30m└─────────────────────────────────────┘\x1b[0m
    `);
    
    res.send(`
      <h1>🌈 Chat Server Running</h1>
      <pre>${JSON.stringify(serverStatus, null, 2)}</pre>
      <h2>Recent Activity</h2>
      <div id="connections"></div>
    `);
  }
});

// Socket.IO setup
const io = new Server(server, {
  cors: corsOptions,
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000,
    skipMiddlewares: true
  },
  transports: ['websocket', 'polling']
});

// Socket.IO middleware
io.use((socket, next) => {
  const attempt = {
    status: 'pending',
    timestamp: new Date().toISOString(),
    origin: socket.handshake.headers.origin,
    ip: socket.handshake.address,
    socketId: socket.id
  };
  
  trackConnection(socket, attempt.status);

  if (socket.handshake.headers.origin === 'http://localhost:5173') {
    const net = require('net');
    const testConnection = net.createConnection({ port: 5173 }, () => {
      testConnection.end();
      attempt.status = 'success';
      console.log(colorful.success(`Port 5173 accessible from ${socket.handshake.address}`));
      next();
    });
    
    testConnection.on('error', (err) => {
      attempt.status = 'failed';
      console.log(colorful.error(`Port 5173 connection failed: ${err.message}`));
      next(new Error('Client port unreachable'));
    });
  } else {
    next();
  }
});

// Initialize default rooms on startup
async function initializeDefaultRooms() {
  try {
    const defaultRooms = [
      { name: 'general', topic: 'General Chat' },
      { name: 'arsenal', topic: 'Arsenal FC Discussions' },
      { name: 'man-u', topic: 'Manchester United FC' },
      { name: 'liverpool', topic: 'Liverpool FC Fan Club' },
      { name: 'bedsa', topic: 'BEDSA Community' }
    ];

    for (const roomData of defaultRooms) {
      const existingRoom = await Room.findOne({ name: roomData.name });
      if (!existingRoom) {
        await Room.create(roomData);
        console.log(colorful.success(`Default room "${roomData.name}" created`));
      }
    }
  } catch (err) {
    console.log(colorful.error(`Error initializing default rooms: ${err.message}`));
  }
}

// Socket.IO connection handler
io.on('connection', async (socket) => {
  // Username tracking
  socket.on('setUsername', (username) => {
    activeUsers.set(socket.id, username);
    console.log(colorful.success(`User ${username} connected`));
  });

  // Room list request
  socket.on('getRoomList', async () => {
    try {
      const rooms = await Room.find();
      const roomList = rooms.map(r => ({
        name: r.name,
        userCount: roomUsers.get(r.name)?.size || 0,
        topic: r.topic
      }));
      socket.emit('roomList', roomList);
    } catch (err) {
      console.log(colorful.error(`Error getting room list: ${err.message}`));
    }
  });

  // Join room
  socket.on('joinRoom', async ({ roomName, username }) => {
    try {
      if (!roomName || !username) {
        throw new Error('Missing room name or username');
      }

      const room = await Room.findOne({ name: roomName });
      if (!room) {
        throw new Error('Room does not exist');
      }

      // Leave previous rooms
      Array.from(socket.rooms)
        .filter(r => r !== socket.id)
        .forEach(room => {
          socket.leave(room);
          const users = roomUsers.get(room);
          if (users) {
            users.delete(username);
            if (users.size === 0) roomUsers.delete(room);
          }
        });

      // Join new room
      socket.join(roomName);
      const usersInRoom = roomUsers.get(roomName) || new Set();
      usersInRoom.add(username);
      roomUsers.set(roomName, usersInRoom);

      // Confirm join to user
      socket.emit('roomJoined', {
        name: roomName,
        userCount: usersInRoom.size,
        topic: room.topic
      });

      // Send room history
      const messages = await Messsage.find({ room: room._id })
        .sort({ createdAt: 1 })
        .limit(50);
      socket.emit('roomHistory', messages);

    } catch (err) {
      console.log(colorful.error(`Join room error: ${err.message}`));
      socket.emit('roomError', { message: err.message });
    }
  });

  socket.on('createRoom', async ({ roomName, username }) => {
    try {
      console.log(colorful.debug(`Create room request: ${roomName} by ${username}`));
      
      if (!roomName || !username) {
        console.log(colorful.error('Room creation failed - Missing fields'));
        return socket.emit('roomError', { message: 'Room name and username are required' });
      }

      const formattedName = roomName.trim().toLowerCase().replace(/\s+/g, '-');
      const existingRoom = await Room.findOne({ name: formattedName });

      if (existingRoom) {
        console.log(colorful.error(`Room ${formattedName} already exists`));
        return socket.emit('roomError', { message: 'Room already exists' });
      }

      const room = await Room.create({
        name: formattedName,
        createdBy: username,
        participants: [username],
        topic: `Chat about ${formattedName}`
      });

      // Join the room immediately after creation
      socket.join(formattedName);
      
      // Track user in new room
      const usersInRoom = new Set([username]);
      roomUsers.set(formattedName, usersInRoom);

      // Get updated room list
      const rooms = await Room.find();
      const roomList = rooms.map(r => ({
        name: r.name,
        userCount: roomUsers.get(r.name)?.size || 0,
        topic: r.topic
      }));
      
      // Emit to all clients
      io.emit('roomList', roomList);
      
      // Confirm to creator
      socket.emit('roomJoined', {
        name: room.name,
        userCount: 1,
        topic: room.topic
      });

      console.log(colorful.success(`Room "${formattedName}" created by ${username}`));
    } catch (err) {
      console.log(colorful.error(`Room creation error: ${err.message}`));
      socket.emit('roomError', { message: 'Failed to create room' });
    }
  });

  // Enhanced message handling with file support
  socket.on('sendMessage', async (message) => {
    try {
      const username = activeUsers.get(socket.id) || 'Anonymous';
      const room = Array.from(socket.rooms).find(r => r !== socket.id);
      
      if (!room) {
        console.log(colorful.warn(`User ${username} tried to send message without joining a room`));
        return;
      }
      
      const roomDoc = await Room.findOne({ name: room });
      if (!roomDoc) {
        console.log(colorful.error(`Room ${room} not found in database`));
        return;
      }
      
      // Create message document with proper fields
      const messageData = {
        content: message.content,
        room: roomDoc._id,
        username: username,
        time: new Date()
      };

      // Add file information if present
      if (message.file) {
        messageData.file = {
          url: message.file.url,
          name: message.file.name,
          type: message.file.type,
          size: message.file.size
        };
        console.log(colorful.success(`File attached: ${message.file.name}`));
        console.log(colorful.debug(`File type: ${message.file.type}, size: ${message.file.size} bytes`));
      }
      
      // Save message to database
      const savedMessage = await Messsage.create(messageData);
      
      // Update room's last activity
      roomDoc.lastActivity = new Date();
      await roomDoc.save();
      
      // Emit message with consistent field names
      const messageToEmit = {
        _id: savedMessage._id,
        username: username,
        content: message.content,
        time: savedMessage.time,
        room: room
      };

      // Add file to emitted message if present
      if (savedMessage.file) {
        messageToEmit.file = savedMessage.file;
        console.log(colorful.debug(`Sending file: ${savedMessage.file.url}`));
      }
      
      io.to(room).emit('message', messageToEmit);
      
      console.log(colorful.debug(`Message from ${username} in ${room}: ${message.content ? message.content.substring(0, 20) + '...' : 'File message'}`));
    } catch (err) {
      console.log(colorful.error(`Message send error: ${err.message}`));
    }
  });

  // File download handler
  socket.on('downloadFile', ({ fileUrl, fileName, fileType }) => {
    console.log(colorful.debug(`File download requested: ${fileUrl}`));
    // Emit the file details to the client
    socket.emit('openFile', { 
      url: fileUrl,
      name: fileName,
      type: fileType 
    });
    console.log(colorful.success(`File opened: ${fileUrl}`));
  });

  // Typing indicators
  socket.on('typing', ({ room }) => {
    const username = activeUsers.get(socket.id) || 'Anonymous';
    io.to(room).emit('typing', { username, room });
    console.log(colorful.debug(`${username} is typing in ${room}`));
  });

  socket.on('stopTyping', ({ room }) => {
    const username = activeUsers.get(socket.id) || 'Anonymous';
    io.to(room).emit('stopTyping', { username, room });
  });

  // Disconnection handler
  socket.on('disconnect', (reason) => {
    const username = activeUsers.get(socket.id);
    if (username) {
      console.log(colorful.warn(`User ${username} disconnected: ${reason}`));
      
      // Remove user from all rooms
      roomUsers.forEach((users, room) => {
        if (users.has(username)) {
          users.delete(username);
          if (users.size === 0) {
            roomUsers.delete(room);
          } else {
            roomUsers.set(room, users);
          }
          console.log(colorful.debug(`User ${username} was imminently removed from room ${room}`));
        }
      });
      
      activeUsers.delete(socket.id);
      
      // Update room list for remaining users
      Room.find().then(rooms => {
        const roomList = rooms.map(r => ({
          name: r.name,
          userCount: roomUsers.get(r.name)?.size || 0,
          topic: r.topic
        }));
        io.emit('roomList', roomList);
      });
    } else {
      console.log(colorful.warn(`Anonymous user disconnected: ${reason}`));
    }
  });

  // Heartbeat monitoring
  const pingInterval = setInterval(() => {
    const start = Date.now();
    socket.emit('💓', start);
    
    socket.once('💗', () => {
      const latency = Date.now() - start;
      console.log(colorful.debug(`Heartbeat from ${socket.id} (${latency}ms)`));
    });
  }, 10000);

  socket.on('disconnect', () => {
    clearInterval(pingInterval);
  });
});

// Admin UI
instrument(io, {
  auth: {
    type: "basic",
    username: "admin",
    password: bcrypt.hashSync("password", 10)
  },
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  namespaceName: "/admin"
});

// Start the server
connectDB().then(async () => {
  await initializeDefaultRooms();
  
  const PORT = process.env.PORT || 5000;
  server.listen(PORT, () => {
    console.log(`
    \x1b[45m\x1b[30m┌─────────────────────────────────────┐\x1b[0m
    \x1b[45m\x1b[30m│ 🚀 SERVER LAUNCH SUCCESSFUL          │\x1b[0m
    \x1b[45m\x1b[30m├─────────────────────────────────────┤\x1b[0m
    │ ${colorful.success(`Port: ${PORT}`)}
    │ ${colorful.success(`Database: Connected`)}
    │ ${colorful.info(`Ready for connections`)}
    \x1b[45m\x1b[30m└─────────────────────────────────────┘\x1b[0m
    
    \x1b[32m     .d8888b.  888     888 
    d88P  Y88b 888     888 
    888    888 888     888 
    888        888     888 
    888  88888 888     888 
    888    888 888     888 
    Y88b  d88P Y88b. .d88P 
     "Y8888P88  "Y88888P"  \x1b[0m
    `);
  });
}).catch(err => {
  console.log(colorful.error(`Database connection failed: ${err.message}`));
  process.exit(1);
});