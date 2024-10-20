import React, { useState } from 'react';

// Placeholder components
const Dashboard = () => <h2>Dashboard</h2>;
const Properties = () => <h2>Properties</h2>;
const Tenants = () => <h2>Tenants</h2>;
const Maintenance = () => <h2>Maintenance Requests</h2>;
const Financials = () => <h2>Financials</h2>;

const Login = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    // Here you would typically make an API call to verify credentials
    onLogin(username);
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button type="submit">Login</button>
    </form>
  );
};

const Navigation = ({ onNavigate, onLogout }) => (
  <nav>
    <ul>
      <li><button onClick={() => onNavigate('dashboard')}>Dashboard</button></li>
      <li><button onClick={() => onNavigate('properties')}>Properties</button></li>
      <li><button onClick={() => onNavigate('tenants')}>Tenants</button></li>
      <li><button onClick={() => onNavigate('maintenance')}>Maintenance</button></li>
      <li><button onClick={() => onNavigate('financials')}>Financials</button></li>
      <li><button onClick={onLogout}>Logout</button></li>
    </ul>
  </nav>
);

const App = () => {
  const [user, setUser] = useState(null);
  const [currentPage, setCurrentPage] = useState('dashboard');

  const handleLogin = (username) => {
    setUser(username);
  };

  const handleLogout = () => {
    setUser(null);
  };

  const handleNavigate = (page) => {
    setCurrentPage(page);
  };

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />;
      case 'properties':
        return <Properties />;
      case 'tenants':
        return <Tenants />;
      case 'maintenance':
        return <Maintenance />;
      case 'financials':
        return <Financials />;
      default:
        return <Dashboard />;
    }
  };

  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <div>
      <Navigation onNavigate={handleNavigate} onLogout={handleLogout} />
      {renderPage()}
    </div>
  );
};

export default App;

