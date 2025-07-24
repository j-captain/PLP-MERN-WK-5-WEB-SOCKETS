import { useState } from 'react';
import AuthForm from '../components/AuthForm';

export default function AuthPage({ onAuthSuccess }) {
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  // Use environment variable or fallback for development
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

  const handleAuth = async (username, password, isLogin) => {
    try {
      // Clear previous errors and set loading state
      setError('');
      setIsLoading(true);

      // Input validation
      if (!username.trim() || !password.trim()) {
        throw new Error('Username and password are required');
      }

      if (password.length < 6) {
        throw new Error('Password must be at least 6 characters');
      }

      const endpoint = isLogin ? '/login' : '/register';
      const response = await fetch(`${API_BASE_URL}/api${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'include'
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.message || 'Authentication failed. Please try again.');
      }

      console.log('Authentication successful', data);
      onAuthSuccess(username, data.token); // Assuming backend returns a token
    } catch (err) {
      console.error('Authentication error:', err);
      setError(err.message || 'Failed to connect to server. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <AuthForm 
        onAuth={handleAuth} 
        error={error} 
        setError={setError}
        isLoading={isLoading}
      />
    </div>
  );
}