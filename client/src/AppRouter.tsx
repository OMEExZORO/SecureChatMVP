import { useState } from 'react';
import App from './App';
import AdminPanel from './components/AdminPanel';
import './index.css';

export default function AppRouter() {
  const [view, setView] = useState<'chat' | 'admin'>('chat');
  const [adminAuthenticated, setAdminAuthenticated] = useState(false);
  const [adminId, setAdminId] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [authError, setAuthError] = useState('');

  const handleAdminLogin = () => {
    // Simple authentication - in production, use proper auth
    if (adminId === 'admin' && adminPassword === 'admin123') {
      setAdminAuthenticated(true);
      setAuthError('');
    } else {
      setAuthError('Invalid admin credentials');
    }
  };

  return (
    <div>
      {/* View Switcher - Only show when not on admin login */}
      {!(view === 'admin' && !adminAuthenticated) && (
        <div className="fixed top-4 right-4 z-50 flex space-x-2">
          <button
            onClick={() => setView('chat')}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              view === 'chat'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            💬 Chat
          </button>
          <button
            onClick={() => {
              setView('admin');
              if (!adminAuthenticated) {
                setAdminId('');
                setAdminPassword('');
                setAuthError('');
              }
            }}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              view === 'admin'
                ? 'bg-purple-600 text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            🔒 Admin
          </button>
        </div>
      )}

      {/* Content */}
      <div style={{ display: view === 'chat' ? 'block' : 'none' }}>
        <App />
      </div>
      
      {view === 'admin' && !adminAuthenticated && (
        // Admin Login Screen
        <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
          <div className="bg-gray-800 rounded-lg shadow-2xl p-8 max-w-md w-full border border-gray-700">
            <div className="text-center mb-6">
              <div className="text-4xl mb-4">🔐</div>
              <h1 className="text-3xl font-bold text-white mb-2">Admin Access</h1>
              <p className="text-gray-400">Enter credentials to view encrypted traffic</p>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Admin ID
                </label>
                <input
                  type="text"
                  value={adminId}
                  onChange={(e) => setAdminId(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  placeholder="Enter admin ID"
                  onKeyPress={(e) => e.key === 'Enter' && handleAdminLogin()}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Admin Password
                </label>
                <input
                  type="password"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  placeholder="Enter admin password"
                  onKeyPress={(e) => e.key === 'Enter' && handleAdminLogin()}
                />
              </div>

              {authError && (
                <div className="bg-red-900/50 border border-red-500 text-red-200 px-4 py-2 rounded-lg text-sm">
                  {authError}
                </div>
              )}

              <div className="bg-blue-900/30 border border-blue-500/50 text-blue-200 px-4 py-3 rounded-lg text-xs">
                <strong>Default Credentials:</strong><br />
                ID: <code className="bg-gray-700 px-2 py-1 rounded">admin</code><br />
                Password: <code className="bg-gray-700 px-2 py-1 rounded">admin123</code>
              </div>

              <button
                onClick={handleAdminLogin}
                className="w-full bg-purple-600 text-white py-3 px-4 rounded-lg hover:bg-purple-700 transition-colors font-medium"
              >
                Access Admin Panel
              </button>

              <button
                onClick={() => setView('chat')}
                className="w-full bg-gray-700 text-gray-300 py-2 px-4 rounded-lg hover:bg-gray-600 transition-colors text-sm"
              >
                Back to Chat
              </button>
            </div>
          </div>
        </div>
      )}

      {view === 'admin' && adminAuthenticated && (
        <div>
          <AdminPanel />
        </div>
      )}
    </div>
  );
}
