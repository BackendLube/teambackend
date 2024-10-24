import React, { useState, useEffect } from 'react'
import { AlertCircle, Building, Users, Wrench, DollarSign, LogOut, PieChart } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'

// Dashboard component now fetches and displays real metrics
const Dashboard = () => {
  const [metrics, setMetrics] = useState({
    totalProperties: 0,
    occupancyRate: 0,
    monthlyIncome: 0
  })

  useEffect(() => {
    // Fetch dashboard metrics when component mounts
    const fetchMetrics = async () => {
      try {
        const response = await fetch('http://localhost:3000/api/dashboard')
        const data = await response.json()
        setMetrics(data)
      } catch (error) {
        console.error('Failed to fetch metrics:', error)
      }
    }
    fetchMetrics()
  }, [])

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6">Dashboard Overview</h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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

// Properties component to display property list
const Properties = () => {
  const [properties, setProperties] = useState([])

  useEffect(() => {
    const fetchProperties = async () => {
      try {
        const response = await fetch('http://localhost:3000/api/properties')
        const data = await response.json()
        setProperties(data.properties)
      } catch (error) {
        console.error('Failed to fetch properties:', error)
      }
    }
    fetchProperties()
  }, [])

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6">Properties</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {properties.map(property => (
          <Card key={property.id}>
            <CardHeader>
              <CardTitle>{property.address}</CardTitle>
            </CardHeader>
            <CardContent>
              <p>{property.description}</p>
              <p className="mt-2">Value: ${property.value.toLocaleString()}</p>
              <p>Performance: {property.performance_metric}%</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

// Tenants component to display tenant list
const Tenants = () => {
  const [tenants, setTenants] = useState([])

  useEffect(() => {
    const fetchTenants = async () => {
      try {
        const response = await fetch('http://localhost:3000/api/tenants')
        const data = await response.json()
        setTenants(data.tenants)
      } catch (error) {
        console.error('Failed to fetch tenants:', error)
      }
    }
    fetchTenants()
  }, [])

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6">Tenants</h2>
      <div className="grid gap-4">
        {tenants.map(tenant => (
          <Card key={tenant.id}>
            <CardContent className="pt-6">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="font-semibold">{tenant.name}</h3>
                  <p>Property ID: {tenant.property_id}</p>
                </div>
                <div className="text-right">
                  <p>Lease: {tenant.lease_start} - {tenant.lease_end}</p>
                  <p>Rent: ${tenant.rent_amount}/month</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

// Maintenance component to display maintenance requests
const Maintenance = () => {
  const [requests, setRequests] = useState([])

  useEffect(() => {
    const fetchMaintenance = async () => {
      try {
        const response = await fetch('http://localhost:3000/api/maintenance')
        const data = await response.json()
        setRequests(data.maintenance_requests)
      } catch (error) {
        console.error('Failed to fetch maintenance requests:', error)
      }
    }
    fetchMaintenance()
  }, [])

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6">Maintenance Requests</h2>
      <div className="grid gap-4">
        {requests.map(request => (
          <Card key={request.id}>
            <CardContent className="pt-6">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="font-semibold">Property ID: {request.property_id}</h3>
                  <p>{request.description}</p>
                </div>
                <div className="text-right">
                  <p>Status: {request.status}</p>
                  <p>Created: {request.created_at}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

// Login component with API integration
const Login = ({ onLogin }) => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      const response = await fetch('http://localhost:3000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })

      if (!response.ok) {
        throw new Error('Invalid credentials')
      }

      const data = await response.json()
      if (data.success) {
        onLogin(username)
      }
    } catch (error) {
      setError('Login failed. Please check your credentials.')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Login to Real Estate Manager</CardTitle>
        </CardHeader>
        <CardContent>
          {error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username (backend)"
              className="w-full p-2 border rounded"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password (team101)"
              className="w-full p-2 border rounded"
            />
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

// Navigation component remains mostly the same but with updated styling
const Navigation = ({ onNavigate, onLogout }) => (
  <nav className="bg-gray-800 text-white p-4">
    <ul className="flex space-x-4">
      <li>
        <button
          onClick={() => onNavigate('dashboard')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <PieChart className="h-4 w-4" />
          Dashboard
        </button>
      </li>
      <li>
        <button
          onClick={() => onNavigate('properties')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <Building className="h-4 w-4" />
          Properties
        </button>
      </li>
      <li>
        <button
          onClick={() => onNavigate('tenants')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <Users className="h-4 w-4" />
          Tenants
        </button>
      </li>
      <li>
        <button
          onClick={() => onNavigate('maintenance')}
          className="flex items-center gap-2 px-3 py-2 rounded hover:bg-gray-700"
        >
          <Wrench className="h-4 w-4" />
          Maintenance
        </button>
      </li>
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

// Main App component
const App = () => {
  const [user, setUser] = useState(null)
  const [currentPage, setCurrentPage] = useState('dashboard')

  const handleLogin = (username) => {
    setUser(username)
  }

  const handleLogout = () => {
    setUser(null)
  }

  const handleNavigate = (page) => {
    setCurrentPage(page)
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />
      case 'properties':
        return <Properties />
      case 'tenants':
        return <Tenants />
      case 'maintenance':
        return <Maintenance />
      case 'financials':
        return <h2 className="p-6 text-2xl font-bold">Financials</h2>
      default:
        return <Dashboard />
    }
  }

  if (!user) {
    return <Login onLogin={handleLogin} />
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <Navigation onNavigate={handleNavigate} onLogout={handleLogout} />
      {renderPage()}
    </div>
  )
}

export default App
