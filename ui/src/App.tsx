import React, { useState, useEffect } from 'react'
import { Activity, Shield, AlertTriangle, Clock, Database, Settings, BarChart3, Brain, Network, Zap } from 'lucide-react'
import ManagementDashboard from './components/ManagementDashboard'
import QueryWorkbench from './components/QueryWorkbench'
import AdvancedDashboard from './components/AdvancedDashboard'
import CentralPortal from './components/CentralPortal'

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
  const [activeView, setActiveView] = useState<'dashboard' | 'query' | 'management' | 'advanced' | 'portal'>('portal')

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const response = await fetch('/api/events')
        if (!response.ok) throw new Error('Failed to fetch events')
        const data = await response.json()
        setEvents(data)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error')
      } finally {
        setLoading(false)
      }
    }

    fetchEvents()
    const interval = setInterval(fetchEvents, 5000) // Refresh every 5s
    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: number) => {
    if (severity >= 4) return 'text-red-600 bg-red-50'
    if (severity >= 3) return 'text-orange-600 bg-orange-50'
    if (severity >= 2) return 'text-yellow-600 bg-yellow-50'
    return 'text-green-600 bg-green-50'
  }

  const getSeverityText = (severity: number) => {
    if (severity >= 4) return 'Critical'
    if (severity >= 3) return 'High'
    if (severity >= 2) return 'Medium'
    return 'Low'
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">MUSAFIR SecOps</h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 text-sm text-gray-500">
                <Database className="h-4 w-4" />
                <span>{events.length} events</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex space-x-8">
          {[
            { id: 'portal', label: 'Central Portal', icon: Zap },
            { id: 'dashboard', label: 'Dashboard', icon: Activity },
            { id: 'query', label: 'Query Workbench', icon: BarChart3 },
            { id: 'management', label: 'Management', icon: Settings },
            { id: 'advanced', label: 'Advanced Security', icon: Shield }
          ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveView(tab.id as any)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeView === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="h-4 w-4 inline mr-2" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="h-screen">
        {activeView === 'portal' && <CentralPortal />}
        {activeView === 'dashboard' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <Activity className="h-8 w-8 text-blue-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Total Events</p>
                    <p className="text-2xl font-semibold text-gray-900">{events.length}</p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <AlertTriangle className="h-8 w-8 text-red-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">High Severity</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {events.filter(e => e.event.severity >= 3).length}
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <Shield className="h-8 w-8 text-green-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Assets</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {new Set(events.map(e => e.asset.id)).size}
                    </p>
                  </div>
                </div>
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <Clock className="h-8 w-8 text-gray-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Last Update</p>
                    <p className="text-sm font-semibold text-gray-900">
                      {events.length > 0 ? new Date(events[0].ts).toLocaleTimeString() : 'N/A'}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Events Table */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h2 className="text-lg font-medium text-gray-900">Security Events</h2>
              </div>
              <div className="overflow-x-auto">
                {loading ? (
                  <div className="p-6 text-center text-gray-500">Loading events...</div>
                ) : error ? (
                  <div className="p-6 text-center text-red-500">Error: {error}</div>
                ) : events.length === 0 ? (
                  <div className="p-6 text-center text-gray-500">No events found</div>
                ) : (
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Time
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Asset
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Event
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Severity
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Details
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {events.map((event, index) => (
                        <tr key={index} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {new Date(event.ts).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">{event.asset.id}</div>
                            <div className="text-sm text-gray-500">{event.asset.os} - {event.asset.ip}</div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900">{event.event.name}</div>
                            <div className="text-sm text-gray-500">{event.event.class}</div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(event.event.severity)}`}>
                              {getSeverityText(event.event.severity)}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <div className="max-w-xs truncate">
                              {event.event.attrs.image && (
                                <div>Process: {event.event.attrs.image}</div>
                              )}
                              {event.event.attrs.cmd && (
                                <div>Command: {event.event.attrs.cmd}</div>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        )}

      {activeView === 'query' && <QueryWorkbench />}
      {activeView === 'management' && <ManagementDashboard />}
      {activeView === 'advanced' && <AdvancedDashboard />}
      </main>
    </div>
  )
}

export default App
