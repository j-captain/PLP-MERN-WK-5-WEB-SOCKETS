import { useState } from 'react';
import AuthForm from '../components/AuthForm';
import { useNavigate } from 'react-router-dom';

export default function AuthPage({ onAuthSuccess }) {
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  
  // Use environment variable for API base URL
  const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

  const handleAuth = async (username, password, isLogin) => {
    try {
      setError('');
      setIsLoading(true);

      // Basic validation
      if (!username.trim() || !password.trim()) {
        throw new Error('Username and password are required');
      }

      const endpoint = isLogin ? '/login' : '/register';
      const response = await fetch(`${API_BASE_URL}/api${endpoint}`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
        credentials: 'include'
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      // Store token and user data
      if (data.token) {
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('username', data.username);
      }

      onAuthSuccess(data.username, data.token);
      navigate('/chat'); // Redirect to chat page
    } catch (err) {
      console.error('Auth error:', err);
      setError(err.message || 'Failed to connect to server');
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