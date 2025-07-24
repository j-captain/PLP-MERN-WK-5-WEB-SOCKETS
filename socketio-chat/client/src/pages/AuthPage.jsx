import { useState } from 'react';
import AuthForm from '../components/AuthForm';



const API_URL = "https://plp-mern-wk-5-web-sockets-backened-0nno.onrender.com/api";


export default function AuthPage({ onAuthSuccess }) {
  const [error, setError] = useState('');

  const handleAuth = async (username, password, isLogin) => {
    try {
      const endpoint = isLogin ? '/api/login' : '/api/register';
      const response = await fetch(`https://plp-mern-wk-5-web-sockets-backened-0nno.onrender.com/api${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'include'
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      onAuthSuccess(username);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <AuthForm 
        onAuth={handleAuth} 
        error={error} 
        setError={setError}
      />
    </div>
  );
}