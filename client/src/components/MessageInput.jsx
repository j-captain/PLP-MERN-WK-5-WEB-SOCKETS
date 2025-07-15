import { useRef } from 'react';
import { useSocket } from '../context/SocketContext';
import { FaPaperclip } from 'react-icons/fa';
const MessageInput = ({ currentRoom }) => {
  const socket = useSocket();
  const messageInputRef = useRef();
  const fileInputRef = useRef();

  const handleTyping = () => {
    if (socket) {
      socket.emit('typing', currentRoom);
    }
  };

  const sendMessage = () => {
    const content = messageInputRef.current.value.trim();
    if (content && socket) {
      socket.emit('send_message', {
        content,
        roomId: currentRoom
      });
      messageInputRef.current.value = '';
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !socket) return;

    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData
      });
      
      if (!response.ok) {
        throw new Error('Upload failed');
      }
      
      const { url } = await response.json();
      socket.emit('send_message', {
        content: url,
        roomId: currentRoom,
        isFile: true,
        fileName: file.name,
        fileType: file.type
      });
    } catch (error) {
      console.error('Upload error:', error);
      alert('File upload failed. Please try again.');
    } finally {
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="p-4 bg-white border-t">
      <div className="flex items-center">
        <button 
          onClick={() => fileInputRef.current.click()}
          className="p-2 text-gray-500 hover:text-gray-700"
          title="Attach file"
        >
          <PaperClip size={20} />
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            className="hidden"
            accept="image/*,.pdf,.doc,.docx,.txt"
          />
        </button>
        
        <input
          type="text"
          ref={messageInputRef}
          onKeyUp={handleTyping}
          onKeyPress={handleKeyPress}
          className="flex-1 border rounded-lg p-2 mx-2"
          placeholder="Type a message..."
        />
        
        <button 
          onClick={sendMessage}
          className="p-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
          title="Send message"
        >
          <Send size={20} />
        </button>
      </div>
    </div>
  );
};

export default MessageInput;