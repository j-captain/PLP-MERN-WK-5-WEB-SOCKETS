import { useState, useEffect } from 'react';
import { useSocket } from '../context/SocketContext';

const OnlineUsers = ({ onSelectUser }) => {
  const [users, setUsers] = useState([]);
  const socket = useSocket();

  useEffect(() => {
    if (!socket) return;

    socket.on('user_list', (userList) => {
      setUsers(userList);
    });

    return () => {
      socket.off('user_list');
    };
  }, [socket]);

  return (
    <div className="w-64 bg-gray-200 p-4 h-full overflow-y-auto">
      <h3 className="font-bold text-lg mb-4">Online Users</h3>
      <ul>
        {users.map((user) => (
          <li 
            key={user._id} 
            className="p-2 hover:bg-gray-300 cursor-pointer"
            onClick={() => onSelectUser(user._id)}
          >
            <span className={`inline-block w-3 h-3 rounded-full mr-2 ${user.online ? 'bg-green-500' : 'bg-gray-500'}`}></span>
            {user.username}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default OnlineUsers;