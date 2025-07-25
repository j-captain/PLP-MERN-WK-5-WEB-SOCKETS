import { useState } from 'react';
import AuthForm from '../components/AuthForm';

export default function AuthPage({ onAuthSuccess }) {
  const [error, setError] = useState('');

  const handleAuth = async (username, password, isLogin) => {
    try {
      const endpoint = isLogin ? '/api/login' : '/api/register';
      const response = await fetch(`http://localhost:5000${endpoint}`, {
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