import { useState, useEffect } from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useNavigate,
  useLocation,
} from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import AuthPage from './pages/AuthPage';
import ChatPage from './pages/ChatPage';
import { SocketProvider } from './context/SocketContext';

function Header({ user, onLogout }) {
  return (
    <header className="w-full bg-gradient-to-r from-blue-600 to-indigo-700 text-white shadow-lg">
      <div className="w-full max-w-6xl mx-auto py-6 px-4 flex flex-col items-center">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <span className="animate-bounce">💬</span>
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-amber-200 to-amber-400">
            My Chat App
          </span>
        </h1>
        {user && (
          <div className="mt-2 text-sm text-blue-100">
            Welcome, {user.username}!
          </div>
        )}
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="w-full bg-gradient-to-r from-gray-800 to-gray-900 text-gray-300">
      <div className="w-full max-w-6xl mx-auto py-6 px-4 text-center">
        <div className="flex justify-center items-center gap-4 mb-2">
          <span className="h-px w-16 bg-gray-600"></span>
          <span className="text-xs">CONNECT • SHARE • CHAT</span>
          <span className="h-px w-16 bg-gray-600"></span>
        </div>
        <p className="text-sm">
          My Chat App.© {new Date().getFullYear()}. All rights reserved.
        </p>
        <p className="text-xs mt-1 text-gray-500">Made with ❤️ for seamless communication</p>
         <p className="text-xs mt-1 text-gray-500">Designed by Mwangi Josphat Karanja</p>
      </div>
    </footer>
  );
}

function Layout({ children, user, onLogout }) {
  return (
    <div className="flex flex-col min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
      <Header user={user} onLogout={onLogout} />
      <main className="flex-grow w-full max-w-6xl mx-auto p-6">
        {children}
      </main>
      <Footer />
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const stored = localStorage.getItem('chatUser');
    if (stored) setUser(JSON.parse(stored));
  }, []);

  const handleAuthSuccess = (username) => {
    const userData = { username };
    setUser(userData);
    localStorage.setItem('chatUser', JSON.stringify(userData));
    navigate('/chat');
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('chatUser');
    navigate('/');
  };

  return (
    <SocketProvider username={user?.username}>
      <Layout user={user} onLogout={handleLogout}>
        <AnimatePresence mode="wait">
          <Routes location={location} key={location.pathname}>
            <Route
              path="/"
              element={
                user ? (
                  <Navigate to="/chat" replace />
                ) : (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.4 }}
                    className="w-full"
                  >
                    <AuthPage onAuthSuccess={handleAuthSuccess} />
                  </motion.div>
                )
              }
            />
            <Route
              path="/chat"
              element={
                user ? (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.4 }}
                    className="w-full"
                  >
                    <ChatPage username={user.username} onLogout={handleLogout} />
                  </motion.div>
                ) : (
                  <Navigate to="/" replace />
                )
              }
            />
          </Routes>
        </AnimatePresence>
      </Layout>
    </SocketProvider>
  );
}

export default function WrappedApp() {
  return (
    <Router>
      <App />
    </Router>
  );
}