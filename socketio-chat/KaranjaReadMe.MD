# MWANGI JOSPHAT KARANJA  WK 5 ASSIGNMENT-Real-Time Chat Application with Socket.io

A full-stack real-time chat application built with React.js, Node.js, Express.js, MongoDB, and Socket.io. This application features real-time messaging, user presence indicators, typing notifications, and more.

## Features

- **Real-time messaging** with Socket.io
- **User authentication** (username-based)
- **Global chat room** for all users
- **Private messaging** between users
- **Typing indicators** when users are composing messages
- **Online/offline status** for users
- **File uploads** (images and documents)
- **Read receipts** for messages
- **Responsive design** with Tailwind CSS

## Technologies Used

### Frontend
- React.js (Vite)
- Socket.io-client
- Tailwind CSS v3
- React Icons
- React Router

### Backend
- Node.js
- Express.js
- Socket.io
- MongoDB (Mongoose)
- Multer (for file uploads)
- JWT (for authentication)

## Installation

### Prerequisites
- Node.js (v18+ recommended)
- MongoDB (local or Atlas URI)
- Git

### Backend Setup

1. Navigate to the server directory:
```bash
cd server
```

2. Install backend dependencies:
```bash
npm install express socket.io mongoose cors dotenv jsonwebtoken bcryptjs multer path
```

3. Create a `.env` file in the server directory with the following variables:
```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
CLIENT_URL=http://localhost:5173
PORT=5000
```

4. Start the backend server:
 
npm run dev
 

### Frontend Setup

1. Navigate to the client directory:
 
cd client
 

2. Install frontend dependencies:
 
npm install socket.io-client react-router-dom react-icons jwt-decode react-feather
npm install tailwindcss @tailwindcss/vite


3. Create a `.env` file in the client directory:
 
VITE_API_BASE_URL=http://localhost:5000
 

4. Start the frontend development server:
 
npm run dev
 

## Project Structure

### Backend
```
server/
├── config/
│   └── db.js            # Database connection
├── controllers/
├── models/
│   ├── User.js          # User model
│   ├── Message.js       # Message model
│   └── Room.js          # Chat room model
├── socket/
│   ├── auth.js          # Socket authentication
│   └── chat.js          # Socket event handlers
├── utils/
├── server.js            # Main server file
└── package.json
```

### Frontend
```
client/
├── public/
├── src/
│   ├── components/
│   │   ├── MessageInput.jsx
│   │   ├── MessageList.jsx
│   │   └── OnlineUsers.jsx
│   ├── context/
│   │   └── SocketContext.jsx
│   ├── hooks/
│   ├── pages/
│   │   └── ChatPage.jsx
│   ├── socket/
│   │   └── socket.js
│   ├── App.jsx
│   ├── main.jsx
│   └── index.css
├── .eslintrc.cjs
├── index.html
├── package.json
└── tailwind.config.js
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login an existing user

### File Upload
- `POST /api/upload` - Upload files (images/documents)

## Socket.io Events

### Server Emits
- `new_message` - When a new message is received
- `previous_messages` - When a user joins a room
- `typing` - When a user is typing
- `user_list` - List of online users
- `private_room_created` - When a private chat is created
- `message_read` - When a message is read by a user

### Client Emits
- `send_message` - Send a new message
- `join_room` - Join a chat room
- `start_private_chat` - Start a private chat
- `mark_as_read` - Mark a message as read
- `typing` - Notify when user is typing

## Dependencies List

### Backend Dependencies
```
"dependencies": {
  "express": "^4.18.2",
  "socket.io": "^4.7.2",
  "mongoose": "^8.0.3",
  "cors": "^2.8.5",
  "dotenv": "^16.3.1",
  "jsonwebtoken": "^9.0.2",
  "bcryptjs": "^2.4.3",
  "multer": "^1.4.5-lts.1",
  "path": "^0.12.7"
},
"devDependencies": {
  "nodemon": "^3.0.2"
}
```

### Frontend Dependencies
```
"dependencies": {
  "react": "^18.2.0",
  "react-dom": "^18.2.0",
  "socket.io-client": "^4.7.2",
  "react-router-dom": "^6.18.0",
  "react-icons": "^4.10.1",
  "jwt-decode": "^3.1.2",
  "react-feather": "^2.0.10"
},
"devDependencies": {
  "@types/react": "^18.2.45",
  "@types/react-dom": "^18.2.18",
  "@vitejs/plugin-react": "^4.2.1",
  "autoprefixer": "^10.4.16",
  "postcss": "^8.4.31",
  "tailwindcss": "^3.3.5",
  "@tailwindcss/forms": "^0.5.6",
  "@tailwindcss/typography": "^0.5.9",
  "vite": "^5.0.8"
}
```

## Deployment

### Backend
Deploy to services like:
- Render
- Railway
- Heroku
- AWS EC2

### Frontend
Deploy to:
- Vercel
- Netlify
- GitHub Pages
- Firebase Hosting

## Troubleshooting

1. **Socket connection issues**:
   - Verify CORS settings
   - Check environment variables
   - Ensure both client and server are running

2. **File uploads not working**:
   - Create the `uploads` directory in server root
   - Check file size and type restrictions
   - Verify Multer configuration

3. **Tailwind CSS not applying**:
   - Check import in vite.config.js
   - Verify `index.css` contains Tailwind directives
   - Restart the Vite dev server

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request


**screenshots**

![image1](<Screenshot (106).png>)
 ![image2](<Screenshot (100).png>) 
 ![image3](<Screenshot (101).png>)
  ![image4](<Screenshot (102).png>) 
  ![image5](<Screenshot (103).png>) 
  ![image6](<Screenshot (104).png>)
   ![image7](<Screenshot (105).png>)


Deployment link: https://github.com/PLP-MERN-Stack-Development/week-5-web-sockets-assignment-j-captain.git
