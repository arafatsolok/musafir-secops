import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import SOCDashboard from './components/SOCDashboard'
import ThreatHunting from './components/ThreatHunting'
import IncidentResponse from './components/IncidentResponse'
import ComplianceCenter from './components/ComplianceCenter'
import ForensicsLab from './components/ForensicsLab'
import ThreatIntelligence from './components/ThreatIntelligence'
import AssetInventory from './components/AssetInventory'
import UserBehaviorAnalytics from './components/UserBehaviorAnalytics'
import VulnerabilityManagement from './components/VulnerabilityManagement'
import AlertCenter from './components/AlertCenter'
import UserManagement from './components/UserManagement'
import QueryWorkbench from './components/QueryWorkbench'
import AdvancedDashboard from './components/AdvancedDashboard'
import CentralPortal from './components/CentralPortal'
import AgentEnrollment from './components/AgentEnrollment'
import Navbar from './components/Navbar'
import Login from './components/Login'
import NotFound from './components/NotFound'
import ProtectedRoute from './components/ProtectedRoute'

interface Event {
  ts: string
  tenant_id: string
  asset: {
    id: string
    type: string
    os: string
    ip: string
  }
  user: {
    id: string
    sid: string
  }
  event: {
    class: string
    name: string
    severity: number
    attrs: Record<string, any>
  }
  ingest: {
    agent_version: string
    schema: string
  }
}

function App() {
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(
    !!localStorage.getItem('auth_token')
  )

  useEffect(() => {
    if (isAuthenticated) {
      fetchEvents();
    }
  }, [isAuthenticated]);

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('auth_token') || '';
      const headers: HeadersInit = token ? { Authorization: `Bearer ${token}` } : {};
      const response = await fetch('/api/events', { headers });
      
      if (!response.ok) {
        if (response.status === 401) {
          // Handle unauthorized
          setIsAuthenticated(false);
          localStorage.removeItem('auth_token');
          throw new Error('Session expired. Please login again.');
        }
        throw new Error('Failed to fetch events');
      }
      
      const data = await response.json();
      setEvents(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = (token: string) => {
    localStorage.setItem('auth_token', token);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    setIsAuthenticated(false);
  };

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-gray-100">
        {isAuthenticated && <Navbar onLogout={handleLogout} />}
        
        <div className="flex-1 overflow-auto">
          <Routes>
            <Route path="/login" element={
              isAuthenticated ? <Navigate to="/dashboard" /> : <Login onLogin={handleLogin} />
            } />
            
            <Route path="/" element={
              isAuthenticated ? <Navigate to="/dashboard" /> : <Navigate to="/login" />
            } />
            
            <Route path="/dashboard" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <SOCDashboard events={events} loading={loading} error={error} />
              </ProtectedRoute>
            } />
            
            <Route path="/threat-hunting" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <ThreatHunting />
              </ProtectedRoute>
            } />
            
            <Route path="/incident-response" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <IncidentResponse />
              </ProtectedRoute>
            } />
            
            <Route path="/compliance" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <ComplianceCenter />
              </ProtectedRoute>
            } />
            
            <Route path="/forensics" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <ForensicsLab />
              </ProtectedRoute>
            } />
            
            <Route path="/threat-intel" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <ThreatIntelligence />
              </ProtectedRoute>
            } />
            
            <Route path="/assets" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <AssetInventory />
              </ProtectedRoute>
            } />
            
            <Route path="/ueba" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <UserBehaviorAnalytics />
              </ProtectedRoute>
            } />
            
            <Route path="/vulnerabilities" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <VulnerabilityManagement />
              </ProtectedRoute>
            } />
            
            <Route path="/alerts" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <AlertCenter />
              </ProtectedRoute>
            } />
            
            <Route path="/users" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <UserManagement />
              </ProtectedRoute>
            } />
            
            <Route path="/query" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <QueryWorkbench />
              </ProtectedRoute>
            } />
            
            <Route path="/advanced" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <AdvancedDashboard />
              </ProtectedRoute>
            } />
            
            <Route path="/portal" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <CentralPortal />
              </ProtectedRoute>
            } />
            
            <Route path="/agents" element={
              <ProtectedRoute isAuthenticated={isAuthenticated}>
                <AgentEnrollment />
              </ProtectedRoute>
            } />
            
            <Route path="*" element={<NotFound />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;
