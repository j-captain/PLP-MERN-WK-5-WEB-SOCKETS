import { io } from 'socket.io-client';

const URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

 
const socket = io('http://localhost:5000', {
  auth: {
    token: localStorage.getItem('authToken')  
  }
});

export const initSocket = (token) => {
  return io(URL, {
    auth: { token },
    autoConnect: false,
  });
};