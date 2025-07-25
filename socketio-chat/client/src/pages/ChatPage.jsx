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
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (!socket) return;

    socket.emit('setUsername', username);
    socket.emit('getRoomList');

    const initSocketListeners = () => {
      socket.on('roomList', roomList => {
        setRooms(roomList);
        if (!currentRoom && roomList.length) {
          const initialRoom = roomList[0].name;
          socket.emit('joinRoom', { roomName: initialRoom, username });
        }
      });

      socket.on('roomJoined', room => {
        setCurrentRoom(room.name);
        setMessages([]);
      });

      socket.on('message', msg => {
        if (msg.room === currentRoom) {
          setMessages(prev => [...prev, msg]);
          setTypingUsers(prev => prev.filter(u => u !== msg.username));
        }
      });

      socket.on('userConnection', data => {
        setOnlineUsers(prev => {
          const s = new Set(prev);
          data.status === 'online' ? s.add(data.username) : s.delete(data.username);
          return [...s];
        });
      });

      socket.on('typing', ({ username: u, room }) => {
        if (room === currentRoom && u !== username) {
          setTypingUsers(prev => (prev.includes(u) ? prev : [...prev, u]));
        }
      });

      socket.on('stopTyping', ({ username: u, room }) => {
        if (room === currentRoom) {
          setTypingUsers(prev => prev.filter(x => x !== u));
        }
      });

      socket.on('roomError', error => {
        console.error('Room error:', error);
        alert(error.message);
      });
    };

    initSocketListeners();

    return () => {
      if (socket) {
        [
          'roomList', 'roomJoined', 'message', 
          'userConnection', 'typing', 'stopTyping',
          'roomError'
        ].forEach(evt => socket.off(evt));
      }
    };
  }, [socket, username, currentRoom]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, typingUsers]);

  const sendMessage = () => {
    if (inputValue.trim() && socket && currentRoom) {
      socket.emit('sendMessage', { 
        content: inputValue, 
        room: currentRoom,
        username
      });
      setInputValue('');
      handleStopTyping();
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const fileType = getFileType(file.type);
    const fileIcon = getFileIcon(fileType);
    
    if (socket && currentRoom) {
      socket.emit('sendMessage', { 
        content: `${fileIcon} ${file.name}`,
        room: currentRoom,
        username,
        isFile: true,
        fileType,
        fileName: file.name,
        fileUrl: URL.createObjectURL(file) // Store the file URL for opening
      });
    }
  };

  const getFileType = (mimeType) => {
    if (mimeType.startsWith('audio/')) return 'audio';
    if (mimeType.startsWith('video/')) return 'video';
    if (mimeType.startsWith('image/')) return 'image';
    if (mimeType.includes('pdf')) return 'pdf';
    if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) return 'ppt';
    if (mimeType.includes('document') || mimeType.includes('msword') || mimeType.includes('wordprocessing')) return 'doc';
    return 'file';
  };

  const getFileIcon = (type) => {
    const icons = {
      audio: '🎵',
      video: '🎬',
      image: '🖼️',
      pdf: '📄',
      ppt: '📊',
      doc: '📝',
      file: '📁'
    };
    return icons[type] || icons.file;
  };

  const handleFileClick = (fileName, fileUrl) => {
    if (fileUrl) {
      // Create a temporary anchor element to trigger the download/open
      const a = document.createElement('a');
      a.href = fileUrl;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      
      // For downloads, you can set the download attribute
      // a.download = fileName;
      
      // Trigger the click
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } else {
      alert(`File URL not available for ${fileName}`);
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
    if (socket && roomName && roomName !== currentRoom) {
      socket.emit('joinRoom', { roomName, username });
    }
  };

  const createRoom = roomName => {
    const name = roomName?.trim();
    if (socket && name) {
      socket.emit('createRoom', { roomName: name, username });
    }
  };

  return (
    <>
      <style>{`
        :root {
          --grad-start: #a18cd1; 
          --grad-end: #fbc2eb;
          --primary-purple: #8e7cc3; 
          --accent-pink: #f48fb1;
          --soft-pink: #ffdeeb;
          --white-semi: rgba(255,255,255,0.9);
          --shadow-md: 0 8px 16px rgba(0,0,0,0.1);
          --shadow-sm: 0 4px 8px rgba(0,0,0,0.05);
          --radius-lg: 1rem;
          --radius-md: 0.75rem;
          --radius-sm: 0.5rem;
        }
        
        body {
          background: linear-gradient(135deg, var(--grad-start), var(--grad-end));
          margin: 0;
          padding: 2rem;
          min-height: 100vh;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
        }
        
        .chat-container {
          display: flex; 
          width: 100%;
          max-width: 1100px;
          height: 80vh;
          min-height: 500px;
          background: white; 
          border-radius: var(--radius-lg);
          overflow: hidden; 
          box-shadow: var(--shadow-md);
          transition: all 0.3s ease;
        }
        
        .sidebar {
          width: 260px;
          background: var(--white-semi);
          backdrop-filter: blur(8px);
          display: flex;
          flex-direction: column;
          border-right: 1px solid rgba(0,0,0,0.05);
        }
        
        .sidebar-header, .sidebar-footer { 
          padding: 1rem; 
          border-bottom: 1px solid rgba(0,0,0,0.05);
        }
        
        .sidebar-footer { 
          margin-top: auto; 
          border-top: 1px solid rgba(0,0,0,0.05);
          border-bottom: none;
        }
        
        .sidebar-body { 
          padding: 1rem; 
          overflow-y: auto; 
          flex: 1; 
        }
        
        .status {
          font-size: 0.8rem;
          padding: 0.25rem 0.5rem;
          border-radius: var(--radius-sm);
          background: rgba(0,0,0,0.05);
        }
        
        .status.online { 
          color: #10b981; 
          background: rgba(16, 185, 129, 0.1);
        } 
        
        .status.offline { 
          color: #ef4444;
          background: rgba(239, 68, 68, 0.1);
        }
        
        .room-header, .users-header {
          display: flex; 
          justify-content: space-between; 
          align-items: center;
          margin-bottom: 0.75rem;
        }
        
        .room-header h3, .users-header h3 {
          margin: 0;
          font-size: 0.95rem;
          color: var(--primary-purple);
          font-weight: 600;
        }
        
        .room-header button {
          background: var(--accent-pink); 
          color: white;
          border: none; 
          border-radius: var(--radius-sm); 
          padding: 0.25rem 0.5rem;
          cursor: pointer;
          font-size: 0.8rem;
          transition: all 0.2s ease;
        }
        
        .room-header button:hover {
          transform: translateY(-1px);
          box-shadow: var(--shadow-sm);
        }
        
        .room-item, .user-item {
          display: flex; 
          align-items: center;
          padding: 0.5rem; 
          margin-bottom: 0.5rem;
          border-radius: var(--radius-md);
          cursor: pointer; 
          transition: all 0.2s ease;
          font-size: 0.9rem;
        }
        
        .room-item:hover, .user-item:hover {
          background: rgba(142,124,195,0.1);
          transform: translateX(2px);
        }
        
        .room-item.active {
          background: rgba(142,124,195,0.2);
          font-weight: 500;
        }
        
        .dot {
          width: 0.5rem; 
          height: 0.5rem; 
          border-radius: 50%;
          margin-right: 0.75rem; 
          background: var(--primary-purple);
          flex-shrink: 0;
        }
        
        .user-online.dot { background: #10b981; }
        
        .room-item .count {
          margin-left: auto; 
          font-size: 0.8rem; 
          color: var(--accent-pink);
          background: var(--soft-pink);
          padding: 0.15rem 0.4rem;
          border-radius: 1rem;
        }
        
        .sidebar-footer .profile {
          display: flex; 
          align-items: center;
        }
        
        .avatar {
          width: 2.5rem; 
          height: 2.5rem;
          background: linear-gradient(135deg, var(--primary-purple), var(--accent-pink)); 
          color: white;
          font-weight: bold; 
          border-radius: 50%;
          display: flex; 
          align-items: center; 
          justify-content: center;
          margin-right: 0.75rem;
          font-size: 1.2rem;
        }
        
        .logout {
          background: none; 
          border: none; 
          color: var(--primary-purple);
          font-size: 0.85rem; 
          cursor: pointer;
          margin-top: 0.25rem;
          transition: color 0.2s ease;
        }
        
        .logout:hover {
          color: var(--accent-pink);
          text-decoration: underline;
        }
        
        .main-chat { 
          flex: 1; 
          display: flex; 
          flex-direction: column; 
        }
        
        .chat-header {
          display: flex; 
          justify-content: space-between; 
          align-items: center;
          padding: 1rem; 
          background: var(--white-semi); 
          backdrop-filter: blur(8px);
          border-bottom: 1px solid rgba(0,0,0,0.05);
        }
        
        .chat-header h1 {
          margin: 0; 
          font-size: 1.25rem; 
          color: var(--primary-purple);
          font-weight: 600;
        }
        
        .summary {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-size: 0.85rem;
          color: var(--primary-purple);
        }
        
        .summary span {
          opacity: 0.8;
        }
        
        .messages {
          flex: 1; 
          padding: 1.5rem; 
          overflow-y: auto;
          background: #faf9fc;
        }
        
        .message-row {
          margin-bottom: 1rem; 
          display: flex;
        }
        
        .message-row.you { justify-content: flex-end; }
        .message-row.other { justify-content: flex-start; }
        
        .message-bubble {
          max-width: 70%;
          background: white; 
          border-radius: var(--radius-md);
          padding: 0.75rem 1rem; 
          box-shadow: var(--shadow-sm);
          position: relative;
          transition: all 0.2s ease;
        }
        
        .message-row.you .message-bubble {
          background: linear-gradient(135deg, var(--primary-purple), var(--accent-pink));
          color: white; 
          border-bottom-right-radius: 0;
        }
        
        .message-row.other .message-bubble {
          border-bottom-left-radius: 0;
          background: white;
        }
        
        .msg-user-label {
          font-size: 0.75rem; 
          font-weight: 600;
          margin-bottom: 0.25rem;
          opacity: 0.8;
        }
        
        .message-row.you .msg-user-label {
          color: rgba(255,255,255,0.9);
        }
        
        .message-row.other .msg-user-label {
          color: var(--primary-purple);
        }
        
        .msg-text { 
          font-size: 0.95rem;
          line-height: 1.4;
        }
        
        .msg-time {
          font-size: 0.65rem; 
          text-align: right;
          margin-top: 0.5rem; 
          opacity: 0.7;
        }
        
        .message-row.you .msg-time {
          color: rgba(255,255,255,0.8);
        }
        
        .message-row.other .msg-time {
          color: #999;
        }
        
        .heart-btn {
          position: absolute; 
          top: -0.5rem; 
          right: -0.5rem;
          background: white; 
          border-radius: 50%;
          width: 1.5rem;
          height: 1.5rem;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: var(--shadow-sm);
          cursor: pointer;
          border: none;
          transition: all 0.2s ease;
        }
        
        .heart-btn:hover {
          transform: scale(1.1);
        }
        
        .heart-icon { 
          width: 0.9rem; 
          height: 0.9rem; 
          color: var(--accent-pink); 
        }
        
        .chat-input-container {
          padding: 1rem; 
          background: var(--white-semi);
          border-top: 1px solid rgba(0,0,0,0.05);
        }
        
        .input-row {
          display: flex; 
          align-items: center; 
          gap: 0.5rem;
        }
        
        .input-row input {
          flex: 1; 
          padding: 0.75rem 1rem;
          border: 1px solid rgba(0,0,0,0.1); 
          border-radius: var(--radius-md);
          font-size: 0.95rem; 
          outline: none;
          transition: all 0.2s ease;
          background: white;
        }
        
        .input-row input:focus {
          border-color: var(--accent-pink);
          box-shadow: 0 0 0 2px rgba(244, 143, 177, 0.2);
        }
        
        .input-row button {
          background: var(--accent-pink); 
          border: none; 
          color: white;
          font-size: 1.1rem; 
          width: 2.5rem;
          height: 2.5rem;
          border-radius: 50%; 
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s ease;
        }
        
        .input-row button:hover {
          transform: scale(1.05);
        }
        
        .input-row button:disabled {
          opacity: 0.4; 
          cursor: not-allowed;
          transform: none !important;
        }
        
        .file-input-btn {
          background: var(--primary-purple) !important;
        }
        
        .file-input {
          display: none;
        }
        
        .file-message {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          cursor: pointer;
          text-decoration: underline;
        }
        
        .file-message:hover {
          color: var(--accent-pink);
        }
        
        .no-messages {
          text-align: center; 
          color: var(--primary-purple);
          height: 100%;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 1rem;
          opacity: 0.6;
        }
        
        .no-messages svg {
          width: 3rem;
          height: 3rem;
          stroke-width: 1.5;
          color: var(--primary-purple);
        }
        
        .no-messages p {
          margin: 0;
          font-size: 0.95rem;
        }
        
        .typing-status {
          margin-top: 0.5rem; 
          display: flex;
          justify-content: flex-end; 
          align-items: center;
          font-size: 0.8rem; 
          color: var(--primary-purple);
          opacity: 0.7;
        }
        
        .typing-indicator-xs {
          display: flex; 
          gap: 4px; 
          margin-left: 0.5rem;
        }
        
        .typing-indicator-xs span {
          width: 0.5rem; 
          height: 0.5rem; 
          background: var(--accent-pink);
          border-radius: 50%;
          animation: blink 1s infinite;
        }
        
        @keyframes blink { 
          0%,100% { opacity: 0.2; } 
          50% { opacity: 1; }
        }
        
        /* Enhanced Media Queries for Mobile */
        @media (max-width: 900px) {
          .chat-container {
            height: 90vh;
            max-width: 95%;
            flex-direction: column;
          }
          
          .sidebar {
            width: 100%;
            border-right: none;
            border-bottom: 1px solid rgba(0,0,0,0.05);
          }
          
          .sidebar-body {
            max-height: 150px;
            overflow-y: auto;
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
          }
          
          .room-header, .users-header {
            width: 100%;
          }
          
          .room-item, .user-item {
            margin-bottom: 0;
            flex: 1 0 calc(50% - 0.5rem);
            min-width: 120px;
          }
          
          .messages {
            padding: 1rem;
          }
          
          .message-bubble {
            max-width: 80%;
          }
        }
        
        @media (max-width: 768px) {
          body {
            padding: 0.5rem;
          }
          
          .chat-container {
            height: 95vh;
            max-height: none;
            border-radius: 0.5rem;
          }
          
          .sidebar-body {
            max-height: 120px;
          }
          
          .message-bubble {
            max-width: 85%;
            padding: 0.6rem 0.8rem;
          }
        }
        
        @media (max-width: 480px) {
          body {
            padding: 0;
          }
          
          .chat-container {
            height: 100vh;
            border-radius: 0;
          }
          
          .chat-header {
            flex-direction: column;
            align-items: flex-start;
            gap: 0.5rem;
            padding: 0.75rem;
          }
          
          .chat-header h1 {
            font-size: 1.1rem;
          }
          
          .summary {
            font-size: 0.75rem;
          }
          
          .messages {
            padding: 0.75rem;
          }
          
          .msg-text {
            font-size: 0.9rem;
          }
          
          .input-row {
            gap: 0.3rem;
          }
          
          .input-row input {
            padding: 0.6rem 0.8rem;
            font-size: 0.9rem;
          }
          
          .input-row button {
            width: 2.2rem;
            height: 2.2rem;
            font-size: 1rem;
          }
          
          .sidebar-body {
            flex-direction: column;
            flex-wrap: nowrap;
            gap: 0.3rem;
          }
          
          .room-item, .user-item {
            flex: 0 0 auto;
            width: 100%;
            padding: 0.3rem;
            font-size: 0.85rem;
          }
          
          .file-input-btn::after {
            content: "📤";
          }
        }
        
        @media (max-width: 360px) {
          .input-row button {
            width: 1.8rem;
            height: 1.8rem;
            font-size: 0.9rem;
          }
          
          .sidebar-body {
            max-height: 100px;
          }
        }
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
              <span>{messages.length} messages</span>
              <span>•</span>
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
                      <div className="msg-text">
                        {msg.isFile ? (
                          <div className="file-message" onClick={() => handleFileClick(msg.fileName || msg.content.replace(/^[^\s]+\s/, ''), msg.fileUrl)}>
                            <span>{getFileIcon(msg.fileType)}</span>
                            <span>{msg.content.replace(/^[^\s]+\s/, '')}</span>
                          </div>
                        ) : msg.content}
                      </div>
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
              <button className="file-input-btn" onClick={() => fileInputRef.current.click()}>
                📤
              </button>
              <input
                type="file"
                ref={fileInputRef}
                className="file-input"
                onChange={handleFileUpload}
                accept="audio/*,video/*,image/*,.pdf,.ppt,.pptx,.doc,.docx"
              />
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