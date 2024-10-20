import React, { useState } from 'react';

// Placeholder components for different sections of the app
const Dashboard = () => <h2>Dashboard</h2>;
const Properties = () => <h2>Properties</h2>;
const Tenants = () => <h2>Tenants</h2>;
const Maintenance = () => <h2>Maintenance Requests</h2>;
const Financials = () => <h2>Financials</h2>;

// Login component to handle user login
const Login = ({ onLogin }) => {
  const [username, setUsername] = useState(''); // State for storing the username
  const [password, setPassword] = useState(''); // State for storing the password

  // Function to handle form submission
  const handleSubmit = (e) => {
    e.preventDefault(); // Prevents default form submission behavior
    // Normally, you would make an API call to verify user credentials here
    onLogin(username); // Calls the onLogin function passed as a prop, sending the username
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)} // Updates username state as the user types
        placeholder="Username"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)} // Updates password state as the user types
        placeholder="Password"
      />
      <button type="submit">Login</button> {/* Submits the form */}
    </form>
  );
};

// Navigation component to handle navigation between pages
const Navigation = ({ onNavigate, onLogout }) => (
  <nav>
    <ul>
      <li><button onClick={() => onNavigate('dashboard')}>Dashboard</button></li> {/* Navigates to Dashboard */}
      <li><button onClick={() => onNavigate('properties')}>Properties</button></li> {/* Navigates to Properties */}
      <li><button onClick={() => onNavigate('tenants')}>Tenants</button></li> {/* Navigates to Tenants */}
      <li><button onClick={() => onNavigate('maintenance')}>Maintenance</button></li> {/* Navigates to Maintenance */}
      <li><button onClick={() => onNavigate('financials')}>Financials</button></li> {/* Navigates to Financials */}
      <li><button onClick={onLogout}>Logout</button></li> {/* Calls onLogout when clicked */}
    </ul>
  </nav>
);

// Main App component
const App = () => {
  const [user, setUser] = useState(null); // State to track whether a user is logged in (null means no user is logged in)
  const [currentPage, setCurrentPage] = useState('dashboard'); // State to track the current page

  // Function to handle user login
  const handleLogin = (username) => {
    setUser(username); // Sets the user to the logged-in username
  };

  // Function to handle user logout
  const handleLogout = () => {
    setUser(null); // Logs the user out by setting user state to null
  };

  // Function to handle page navigation
  const handleNavigate = (page) => {
    setCurrentPage(page); // Sets the current page based on user selection
  };

  // Function to render the appropriate page component based on currentPage state
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
        return <Dashboard />; // Defaults to Dashboard if no page matches
    }
  };

  // If no user is logged in, show the Login component
  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  // If a user is logged in, show the Navigation and current page
  return (
    <div>
      <Navigation onNavigate={handleNavigate} onLogout={handleLogout} /> {/* Renders the navigation menu */}
      {renderPage()} {/* Renders the selected page */}
    </div>
  );
};

export default App; // Exports the App component as default


export default App;

