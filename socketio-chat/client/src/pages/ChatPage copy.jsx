import { useEffect, useRef, useState } from 'react';
import { useSocket } from '../context/SocketContext';

export default function ChatPage({ username, onLogout }) {
  const { socket, isConnected } = useSocket();
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [typingUsers, setTypingUsers] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const [rooms, setRooms] = useState([]);
  const [currentRoom, setCurrentRoom] = useState(null);
  const typingTimeout = useRef(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    if (!socket) return;

    // Set username once when component mounts
    socket.emit('setUsername', username);

    // Initialize socket listeners
    const initSocketListeners = () => {
      socket.on('roomList', roomList => {
        console.log('Received room list:', roomList);
        setRooms(roomList);
        if (!currentRoom && roomList.length) {
          // Join the first room if no room is selected
          const initialRoom = roomList[0].name;
          console.log('Joining initial room:', initialRoom);
          socket.emit('joinRoom', { roomName: initialRoom, username });
        }
      });

      socket.on('roomJoined', room => {
        console.log('Joined room:', room);
        setCurrentRoom(room.name);
        setMessages([]); // Clear messages when joining a new room
      });

      socket.on('message', msg => {
        console.log('Received message:', msg);
        // Only add message if it's for the current room
        if (msg.room === currentRoom) {
          setMessages(prev => [...prev, msg]);
          setTypingUsers(prev => prev.filter(u => u !== msg.username));
        }
      });

      socket.on('userConnection', data => {
        console.log('User connection:', data);
        setOnlineUsers(prev => {
          const s = new Set(prev);
          data.status === 'online' ? s.add(data.username) : s.delete(data.username);
          return [...s];
        });
      });

      socket.on('typing', ({ username: u, room }) => {
        console.log(`${u} is typing in ${room}`);
        if (room === currentRoom && u !== username) {
          setTypingUsers(prev => (prev.includes(u) ? prev : [...prev, u]));
        }
      });

      socket.on('stopTyping', ({ username: u, room }) => {
        console.log(`${u} stopped typing in ${room}`);
        if (room === currentRoom) {
          setTypingUsers(prev => prev.filter(x => x !== u));
        }
      });

      socket.on('error', error => {
        console.error('Socket error:', error);
      });
    };

    initSocketListeners();

    // Request initial room list
    socket.emit('getRoomList');

    // Clean up listeners
    return () => {
      if (socket) {
        [
          'message', 
          'userConnection', 
          'typing', 
          'stopTyping', 
          'roomList', 
          'roomJoined',
          'error'
        ].forEach(evt => socket.off(evt));
      }
    };
  }, [socket, username, currentRoom]);

  // Request room list when connection status changes
  useEffect(() => {
    if (socket && isConnected) {
      socket.emit('getRoomList');
    }
  }, [socket, isConnected]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, typingUsers]);

  const sendMessage = () => {
    if (inputValue.trim() && socket && currentRoom) {
      console.log('Sending message:', inputValue, 'to room:', currentRoom);
      socket.emit('sendMessage', { 
        content: inputValue, 
        room: currentRoom,
        username 
      });
      setInputValue('');
      handleStopTyping();
    }
  };

  const handleInputChange = e => {
    setInputValue(e.target.value);
    if (!isTyping) {
      setIsTyping(true);
      socket.emit('typing', { room: currentRoom, username });
    }
    clearTimeout(typingTimeout.current);
    typingTimeout.current = setTimeout(handleStopTyping, 3000);
  };

  const handleStopTyping = () => {
    if (isTyping) {
      setIsTyping(false);
      socket.emit('stopTyping', { room: currentRoom, username });
    }
    clearTimeout(typingTimeout.current);
  };

  const joinRoom = roomName => {
    if (socket && roomName !== currentRoom) {
      console.log('Attempting to join room:', roomName);
      socket.emit('joinRoom', { roomName, username });
    }
  };

  const createRoom = roomName => {
    const name = roomName?.trim();
    if (socket && name) {
      console.log('Creating new room:', name);
      socket.emit('createRoom', { roomName: name, username });
    }
  };

  return (
    <>
      <style>{`
        :root {
          --grad-start: #a18cd1; --grad-end: #fbc2eb;
          --primary-purple: #8e7cc3; --accent-pink: #f48fb1;
          --white-semi: rgba(255,255,255,0.9);
          --shadow-md: 0 8px 16px rgba(0,0,0,0.2);
          --radius-lg: 1rem;
        }
        body {
          background: linear-gradient(135deg, var(--grad-start), var(--grad-end));
          margin: 0; padding: 2rem 0;
          font-family: 'Inter', sans-serif;
        }
        .chat-container {
          display: flex; width: 100%; max-width: 1100px; margin: auto;
          height: auto; max-height: 90vh;
          background: white; border-radius: var(--radius-lg);
          overflow: hidden; box-shadow: var(--shadow-md);
        }
        .sidebar {
          width: 260px; background: var(--white-semi); backdrop-filter: blur(8px);
          display: flex; flex-direction: column;
        }
        .sidebar-header, .sidebar-footer { padding: 1rem; border-bottom: 1px solid #eee; }
        .sidebar-footer { margin-top: auto; border-top: 1px solid #eee; }
        .sidebar-body { padding: 1rem; overflow-y: auto; flex: 1; }
        .status.online { color: green; } .status.offline { color: red; }
        .room-header, .users-header {
          display: flex; justify-content: space-between; margin-bottom: 0.5rem;
        }
        .room-header button {
          background: var(--accent-pink); color: white;
          border: none; border-radius: 0.5rem; padding: 0.25rem 0.5rem;
          cursor: pointer;
        }
        .room-item, .user-item {
          display: flex; align-items: center;
          padding: 0.5rem; margin-bottom: 0.25rem;
          border-radius: 0.75rem;
          cursor: pointer; transition: background .2s;
        }
        .room-item:hover, .user-item:hover {
          background: rgba(142,124,195,0.1);
        }
        .room-item.active {
          background: rgba(142,124,195,0.2);
        }
        .dot {
          width: 0.5rem; height: 0.5rem; border-radius: 50%;
          margin-right: 0.5rem; background: var(--primary-purple);
        }
        .user-online.dot { background: green; }
        .room-item .count {
          margin-left: auto; font-size: 0.8rem; color: var(--accent-pink);
        }
        .sidebar-footer .profile {
          display: flex; align-items: center;
        }
        .avatar {
          width: 2.5rem; height: 2.5rem;
          background: var(--accent-pink); color: white;
          font-weight: bold; border-radius: 50%;
          display: flex; align-items: center; justify-content: center;
          margin-right: 0.75rem;
        }
        .logout {
          background: none; border: none; color: var(--primary-purple);
          font-size: 0.85rem; cursor: pointer;
          margin-top: 0.25rem;
        }
        .main-chat { flex: 1; display: flex; flex-direction: column; }
        .chat-header {
          display: flex; justify-content: space-between; align-items: center;
          padding: 1rem; background: var(--white-semi); backdrop-filter: blur(8px);
          border-bottom: 1px solid #eee;
        }
        .chat-header h1 {
          margin: 0; font-size: 1.5rem; color: var(--primary-purple);
        }
        .summary span {
          font-size: 0.9rem; color: var(--primary-purple);
          margin-left: 0.5rem;
        }
        .messages {
          flex: 1; padding: 2rem; overflow-y: auto;
          background: #f6f5f8;
        }
        .message-row {
          margin-bottom: 1rem; display: flex;
        }
        .message-row.you { justify-content: flex-end; }
        .message-row.other { justify-content: flex-start; }
        .message-bubble {
          max-width: 60%;
          background: white; border-radius: 1rem;
          padding: 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.1);
          position: relative;
        }
        .message-row.you .message-bubble {
          background: linear-gradient(135deg, var(--primary-purple), var(--accent-pink));
          color: white; border-bottom-right-radius: 0;
        }
        .message-row.other .message-bubble {
          border-bottom-left-radius: 0;
        }
        .msg-user-label {
          font-size: 0.8rem; font-weight: 600;
          margin-bottom: 0.25rem;
        }
        .msg-text { font-size: 1rem; }
        .msg-time {
          font-size: 0.7rem; text-align: right;
          margin-top: 0.5rem; color: #999;
        }
        .heart-btn {
          position: absolute; top: -0.5rem; right: -0.5rem;
          background: white; border-radius: 50%;
          padding: 0.25rem;
          box-shadow: 0 2px 5px rgba(0,0,0,0.1);
          cursor: pointer;
        }
        .heart-icon { width: 1rem; height: 1rem; color: pink; }
        .chat-input-container {
          padding: 1rem; background: var(--white-semi);
          border-top: 1px solid #eee;
        }
        .input-row {
          display: flex; align-items: center; gap: 0.5rem;
        }
        .input-row input {
          flex: 1; padding: 0.75rem 1rem;
          border: 1px solid #ddd; border-radius: 1rem;
          font-size: 1rem; outline: none;
        }
        .input-row button {
          background: var(--accent-pink); border: none; color: white;
          font-size: 1.25rem; padding: 0.75rem;
          border-radius: 50%; cursor: pointer;
        }
        .input-row button:disabled {
          opacity: 0.4; cursor: not-allowed;
        }
        .no-messages {
          text-align: center; color: var(--primary-purple);
        }
        .typing-status {
          margin-top: 0.5rem; display: flex;
          justify-content: flex-end; align-items: center;
          font-size: 0.85rem; color: var(--primary-purple);
        }
        .typing-indicator-xs {
          display: flex; gap: 4px; margin-left: 0.5rem;
        }
        .typing-indicator-xs span {
          width: 0.5rem; height: 0.5rem; background: pink;
          border-radius: 50%;
          animation: blink 1s infinite;
        }
        @keyframes blink { 0%,100% { opacity: 0.2; } 50% { opacity: 1; }}
      `}</style>

      <div className="chat-container">
        <aside className="sidebar">
          <div className="sidebar-header">
            <h2>Chat Rooms</h2>
            {isConnected
              ? <span className="status online">Connected</span>
              : <span className="status offline">Disconnected</span>}
          </div>
          <div className="sidebar-body">
            <div className="room-header">
              <h3>Available Rooms</h3>
              <button onClick={() => {
                const n = prompt("Enter new room name:");
                createRoom(n);
              }}>+ New</button>
            </div>
            {rooms.map((room, i) => (
              <div
                key={i}
                className={`room-item ${currentRoom === room.name ? 'active' : ''}`}
                onClick={() => joinRoom(room.name)}
              >
                <span className="dot"></span>
                {room.name}
                <span className="count">{room.userCount || 0}</span>
              </div>
            ))}
            <div className="users-header"><h3>Online Users</h3></div>
            {onlineUsers.map((user, i) => (
              <div key={i} className="user-item">
                <span className="dot user-online"></span>
                {user}{user === username ? ' (You)' : ''}
                {typingUsers.includes(user) && (
                  <span className="typing-indicator-xs">
                    <span></span><span></span><span></span>
                  </span>
                )}
              </div>
            ))}
          </div>
          <div className="sidebar-footer">
            <div className="profile">
              <div className="avatar">{username.charAt(0).toUpperCase()}</div>
              <div>
                <div>{username}</div>
                <div>Room: {currentRoom || 'None'}</div>
                <button onClick={onLogout} className="logout">Sign Out</button>
              </div>
            </div>
          </div>
        </aside>

        <section className="main-chat">
          <div className="chat-header">
            <h1>{currentRoom || 'Select a room'}</h1>
            <div className="summary">
              <span>{messages.length} messages</span><span>•</span>
              <span>{onlineUsers.length} online</span>
            </div>
          </div>

          <div className="messages">
            {messages.length === 0 ? (
              <div className="no-messages">
                <svg xmlns="http://www.w3.org/2000/svg" className="icon-empty" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                    d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/>
                </svg>
                <p>No messages yet in {currentRoom || 'this room'}</p>
                <p>Your messages will appear here</p>
              </div>
            ) : (
              <>
                {messages.map((msg, i) => (
                  <div key={i} className={`message-row ${msg.username === username ? 'you' : 'other'}`}>
                    <div className="message-bubble">
                      <div className="msg-user-label">
                        {msg.username === username ? 'You' : msg.username}
                      </div>
                      <div className="msg-text">{msg.content}</div>
                      <div className="msg-time">
                        {new Date(msg.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit'})}
                      </div>
                      {msg.username !== username && (
                        <button className="heart-btn">
                          <svg xmlns="http://www.w3.org/2000/svg" className="heart-icon" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z" clipRule="evenodd" />
                          </svg>
                        </button>
                      )}
                    </div>
                  </div>
                ))}
                {typingUsers.filter(u => u !== username).map((user, i) => (
                  <div key={i} className="message-row other">
                    <div className="message-bubble">
                      <div className="msg-user-label">{user}</div>
                      <div className="typing-indicator-xs">
                        <span/><span/><span/>
                      </div>
                    </div>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </>
            )}
          </div>

          <div className="chat-input-container">
            <div className="input-row">
              <button>😀</button>
              <input
                type="text"
                value={inputValue}
                onChange={handleInputChange}
                onKeyPress={e => e.key === 'Enter' && sendMessage()}
                onBlur={handleStopTyping}
                placeholder={`Message in ${currentRoom || 'room'}...`}
                disabled={!currentRoom}
              />
              <button onClick={sendMessage} disabled={!inputValue.trim() || !currentRoom}>➤</button>
            </div>
            {isTyping && (
              <div className="typing-status">
                <span>You're typing</span>
                <div className="typing-indicator-xs">
                  <span/><span/><span/>
                </div>
              </div>
            )}
          </div>
        </section>
      </div>
    </>
  );
}