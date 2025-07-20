import { useState } from 'react';

export default function AuthForm({ onAuth, error, setError }) {
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const formData = new FormData(e.target);
    const username = formData.get('username');
    const password = formData.get('password');

    await onAuth(username, password, isLogin);
    setLoading(false);
  };

  return (
    <div className="page-container">
      <div className="auth-container">
        <h1 className="auth-title">
          {isLogin ? 'Sign In' : 'Create Account'}
        </h1>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username" className="form-label">
              Username
            </label>
            <input
              id="username"
              name="username"
              type="text"
              required
              className="form-input"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password" className="form-label">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              required
              minLength="6"
              className="form-input"
            />
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="submit-button"
            >
              {loading ? 'Processing...' : isLogin ? 'Sign In' : 'Register'}
            </button>
          </div>
        </form>

        <div className="auth-toggle">
          <button
            type="button"
            onClick={() => setIsLogin(!isLogin)}
            className="toggle-button"
          >
            {isLogin ? 'Need an account? Register' : 'Already have an account? Sign In'}
          </button>
        </div>

        <style jsx>{`
          .page-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 1rem;
            background-color: #f9fafb;
          }
          
          .auth-container {
            width: 100%;
            max-width: 28rem;
            padding: 2rem;
            background-color: #ffffff;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            animation: fadeIn 0.3s ease-out;
          }
          
          .auth-title {
            font-size: 1.5rem;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 1.5rem;
            text-align: center;
            color: #1e293b;
          }
          
          .error-message {
            padding: 0.75rem;
            font-size: 0.875rem;
            color: #b91c1c;
            background-color: #fee2e2;
            border-radius: 0.375rem;
            margin-bottom: 1rem;
          }
          
          .auth-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
          }
          
          .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
          }
          
          .form-label {
            font-size: 0.875rem;
            font-weight: 500;
            color: #374151;
          }
          
          .form-input {
            width: 100%;
            padding: 0.5rem 0.75rem;
            border: 1px solid #d1d5db;
            border-radius: 0.375rem;
            font-size: 0.875rem;
            transition: all 0.2s ease;
          }
          
          .form-input:focus {
            outline: none;
            border-color: #6366f1;
            box-shadow: 0 0 0 1px #6366f1;
          }
          
          .submit-button {
            width: 100%;
            padding: 0.5rem;
            background-color: #6366f1;
            color: white;
            border: none;
            border-radius: 0.375rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
          }
          
          .submit-button:hover {
            background-color: #4f46e5;
            transform: translateY(-1px);
          }
          
          .submit-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
          }
          
          .auth-toggle {
            text-align: center;
            margin-top: 1rem;
            font-size: 0.875rem;
          }
          
          .toggle-button {
            color: #6366f1;
            font-weight: 500;
            background: none;
            border: none;
            padding: 0;
            cursor: pointer;
            box-shadow: none;
          }
          
          .toggle-button:hover {
            color: #4f46e5;
            text-decoration: underline;
            transform: none;
          }
          
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
          
          @keyframes blink {
            0%, 100% {
              opacity: 0.2;
            }
            50% {
              opacity: 1;
            }
          }
        `}</style>
      </div>
    </div>
  );
}