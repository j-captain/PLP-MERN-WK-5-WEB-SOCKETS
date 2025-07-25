import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'
import { io } from 'socket.io-client'

// Create Socket.IO client connection
const socket = io(import.meta.env.VITE_SERVER_URL || 'https://plp-mern-wk-5-web-sockets-1.onrender.com', {
  withCredentials: true,
  autoConnect: false, // We'll manually connect after auth
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  transports: ['websocket']
})

// For development logging (remove in production)
if (import.meta.env.DEV) {
  socket.on('connect', () => {
    console.log('⚡️ WebSocket connected:', socket.id)
  })

  socket.on('disconnect', () => {
    console.log('⚠️ WebSocket disconnected')
  })

  socket.on('connect_error', (err) => {
    console.error('❌ Connection error:', err.message)
  })
}

// Make socket available via React context if needed
export const SocketContext = React.createContext(socket)

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <SocketContext.Provider value={socket}>
      <App />
    </SocketContext.Provider>
  </React.StrictMode>
)