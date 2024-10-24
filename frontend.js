import React, { useState, useEffect } from 'react'
// Import necessary icons from lucide-react
import { AlertCircle, Building, Users, Wrench, DollarSign, LogOut, PieChart } from 'lucide-react'
// Import UI components from shadcn/ui
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'

// Default property structure
const Property = {
  id: 0,
  description: '',
  photos: [],
  performance_metric: 0
}

// Default maintenance request structure
const MaintenanceRequest = {
  id: 0,
  property_id: 0,
  description: '',
  status: 'Open'
}

// Dashboard component displays overview metrics and property information
const Dashboard = () => {
  // State for storing property list
  const [properties, setProperties] = useState([])
  // State for storing dashboard metrics
  const [metrics, setMetrics] = useState({ totalProperties: 0, occupancyRate: 0, monthlyIncome: 0 })

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6">Dashboard Overview</h2>
      {/* Grid layout for metric cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Properties card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Building className="h-4 w-4" />
              Properties
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{metrics.totalProperties}</p>
          </CardContent>
        </Card>
        {/* Occupancy rate card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PieChart className="h-4 w-4" />
              Occupancy Rate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{metrics.occupancyRate}%</p>
          </CardContent>
        </Card>
        {/* Monthly income card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DollarSign className="h-4 w-4" />
              Monthly Income
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">${metrics.monthlyIncome.toLocaleString()}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// Login component handles user authentication
const Login = ({ onLogin }) => {
  // State for form inputs and error message
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault()
    
    // Check hardcoded credentials
    if (username === 'backend' && password === 'team101') {
      onLogin(username)
    } else {
      setError('Invalid credentials. Please use username: backend, password: team101')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Login to Real Estate Manager</CardTitle>
        </CardHeader>
        <CardContent>
          {/* Error message display */}
          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {/* Login form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username (backend)"
                className="w-full p-2 border rounded"
              />
            </div>
            <div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password (team101)"
                className="w-full p-2 border rounded"
              />
            </div>
            <button
              type="submit"
              className="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700"
            >
              Login
            </button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}

// Navigation component provides the top navigation bar
const Navigation = ({ onNavigate, onLogout }) => (
  <nav className="bg-gray-800 text-white p-4">
    {/* Navigation menu */}
    <ul className="flex space-x-4">
      {/* Dashboard button */}
      <li>
        <button
          onClick={() => onNavigate('dashboard')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <PieChart className="h-4 w-4" />
          Dashboard
        </button>
      </li>
      {/* Properties button */}
      <li>
        <button
          onClick={() => onNavigate('properties')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <Building className="h-4 w-4" />
          Properties
        </button>
      </li>
      {/* Tenants button */}
      <li>
        <button
          onClick={() => onNavigate('tenants')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <Users className="h-4 w-4" />
          Tenants
        </button>
      </li>
      {/* Maintenance button */}
      <li>
        <button
          onClick={() => onNavigate('maintenance')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <Wrench className="h-4 w-4" />
          Maintenance
        </button>
      </li>
      {/* Financials button */}
      <li>
        <button
          onClick={() => onNavigate('financials')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <DollarSign className="h-4 w-4" />
          Financials
        </button>
      </li>
      {/* Logout button */}
      <li className="ml-auto">
        <button
          onClick={onLogout}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <LogOut className="h-4 w-4" />
          Logout
        </button>
      </li>
    </ul>
  </nav>
)

// Main App component manages the application state and routing
const App = () => {
  // State for managing logged-in user
  const [user, setUser] = useState(null)
  // State for managing current page
  const [currentPage, setCurrentPage] = useState('dashboard')

  // Handle user login
  const handleLogin = (username) => {
    setUser(username)
  }

  // Handle user logout
  const handleLogout = () => {
    setUser(null)
  }

  // Handle page navigation
  const handleNavigate = (page) => {
    setCurrentPage(page)
  }

  // Render the appropriate page based on current route
  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />
      case 'properties':
        return <h2 className="p-6 text-2xl font-bold">Properties</h2>
      case 'tenants':
        return <h2 className="p-6 text-2xl font-bold">Tenants</h2>
      case 'maintenance':
        return <h2 className="p-6 text-2xl font-bold">Maintenance Requests</h2>
      case 'financials':
        return <h2 className="p-6 text-2xl font-bold">Financials</h2>
      default:
        return <Dashboard />
    }
  }

  // Show login page if no user is logged in
  if (!user) {
    return <Login onLogin={handleLogin} />
  }

  // Show main application layout when user is logged in
  return (
    <div className="min-h-screen bg-gray-100">
      <Navigation onNavigate={handleNavigate} onLogout={handleLogout} />
      {renderPage()}
    </div>
  )
}

export default App
