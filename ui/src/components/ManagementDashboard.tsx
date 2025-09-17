import React, { useState, useEffect } from 'react'
import { 
  Settings, 
  Play, 
  Square, 
  RotateCcw, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Server,
  Database,
  FileText,
  Cog,
  RefreshCw
} from 'lucide-react'

interface Service {
  name: string
  Name: string
  URL: string
  Port: string
  Health: string
  Enabled: boolean
}

interface ServiceHealth {
  service: string
  status: string
  url: string
  uptime?: string
  error?: string
}

interface LogEntry {
  timestamp: string
  service: string
  level: string
  message: string
}

const ManagementDashboard: React.FC = () => {
  const [services, setServices] = useState<Service[]>([])
  const [healthChecks, setHealthChecks] = useState<ServiceHealth[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [config, setConfig] = useState<any>({})
  const [loading, setLoading] = useState(true)
  const [selectedService, setSelectedService] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'services' | 'monitoring' | 'logs' | 'config'>('services')

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000) // Refresh every 5s
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [servicesRes, healthRes, logsRes, configRes] = await Promise.all([
        fetch('/api/services'),
        fetch('/api/health'),
        fetch('/api/logs'),
        fetch('/api/config')
      ])

      if (servicesRes.ok) {
        const servicesData = await servicesRes.json()
        setServices(Object.values(servicesData))
      }

      if (healthRes.ok) {
        const healthData = await healthRes.json()
        setHealthChecks(healthData)
      }

      if (logsRes.ok) {
        const logsData = await logsRes.json()
        setLogs(logsData)
      }

      if (configRes.ok) {
        const configData = await configRes.json()
        setConfig(configData)
      }
    } catch (err) {
      console.error('Failed to fetch data:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleServiceAction = async (action: 'start' | 'stop' | 'restart', serviceName: string) => {
    try {
      const response = await fetch(`/api/services/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: serviceName })
      })
      
      if (response.ok) {
        alert(`Service ${serviceName} ${action}ed successfully`)
        fetchData() // Refresh data
      }
    } catch (err) {
      console.error(`Failed to ${action} service:`, err)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-green-600 bg-green-50'
      case 'degraded': return 'text-yellow-600 bg-yellow-50'
      case 'unhealthy': return 'text-red-600 bg-red-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="h-4 w-4" />
      case 'degraded': return <AlertTriangle className="h-4 w-4" />
      case 'unhealthy': return <XCircle className="h-4 w-4" />
      default: return <Server className="h-4 w-4" />
    }
  }

  const getLogLevelColor = (level: string) => {
    switch (level) {
      case 'ERROR': return 'text-red-600'
      case 'WARN': return 'text-yellow-600'
      case 'INFO': return 'text-blue-600'
      case 'DEBUG': return 'text-gray-600'
      default: return 'text-gray-600'
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Loading management data...</span>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b px-6 py-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold text-gray-900">Management Dashboard</h1>
          <button
            onClick={fetchData}
            className="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white border-b">
        <nav className="flex space-x-8 px-6">
          {[
            { id: 'services', label: 'Services', icon: Server },
            { id: 'monitoring', label: 'Monitoring', icon: Activity },
            { id: 'logs', label: 'Logs', icon: FileText },
            { id: 'config', label: 'Configuration', icon: Cog }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-4 w-4 inline mr-2" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Content */}
      <div className="flex-1 p-6 overflow-auto">
        {activeTab === 'services' && (
          <div className="space-y-6">
            <h2 className="text-lg font-medium text-gray-900">Service Management</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {services.map((service) => {
                const health = healthChecks.find(h => h.service === service.name)
                return (
                  <div key={service.name} className="bg-white rounded-lg shadow p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center">
                        <Server className="h-5 w-5 text-gray-400 mr-2" />
                        <h3 className="text-lg font-medium text-gray-900">{service.Name}</h3>
                      </div>
                      <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(health?.status || 'unknown')}`}>
                        {getStatusIcon(health?.status || 'unknown')}
                        <span className="ml-1">{health?.status || 'unknown'}</span>
                      </span>
                    </div>
                    
                    <div className="space-y-2 text-sm text-gray-600 mb-4">
                      <div>Port: {service.Port}</div>
                      <div>URL: {service.URL}</div>
                      <div>Enabled: {service.Enabled ? 'Yes' : 'No'}</div>
                      {health?.error && (
                        <div className="text-red-600">Error: {health.error}</div>
                      )}
                    </div>

                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleServiceAction('start', service.name)}
                        className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700"
                      >
                        <Play className="h-4 w-4 mr-1" />
                        Start
                      </button>
                      <button
                        onClick={() => handleServiceAction('stop', service.name)}
                        className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700"
                      >
                        <Square className="h-4 w-4 mr-1" />
                        Stop
                      </button>
                      <button
                        onClick={() => handleServiceAction('restart', service.name)}
                        className="flex-1 inline-flex items-center justify-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                      >
                        <RotateCcw className="h-4 w-4 mr-1" />
                        Restart
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {activeTab === 'monitoring' && (
          <div className="space-y-6">
            <h2 className="text-lg font-medium text-gray-900">System Monitoring</h2>
            
            {/* Health Overview */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <CheckCircle className="h-8 w-8 text-green-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Healthy</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {healthChecks.filter(h => h.status === 'healthy').length}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <AlertTriangle className="h-8 w-8 text-yellow-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Degraded</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {healthChecks.filter(h => h.status === 'degraded').length}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <XCircle className="h-8 w-8 text-red-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Unhealthy</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {healthChecks.filter(h => h.status === 'unhealthy').length}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-lg shadow p-6">
                <div className="flex items-center">
                  <Server className="h-8 w-8 text-blue-600" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-500">Total Services</p>
                    <p className="text-2xl font-semibold text-gray-900">{healthChecks.length}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Detailed Health Table */}
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Service Health Details</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Error</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {healthChecks.map((health, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {health.service}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(health.status)}`}>
                            {getStatusIcon(health.status)}
                            <span className="ml-1">{health.status}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {health.url}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-red-600">
                          {health.error || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="space-y-6">
            <h2 className="text-lg font-medium text-gray-900">System Logs</h2>
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Recent Logs</h3>
              </div>
              <div className="overflow-x-auto max-h-96">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Level</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Message</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {logs.map((log, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {log.service}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`text-xs font-semibold ${getLogLevelColor(log.level)}`}>
                            {log.level}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900">
                          {log.message}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'config' && (
          <div className="space-y-6">
            <h2 className="text-lg font-medium text-gray-900">System Configuration</h2>
            <div className="bg-white shadow rounded-lg">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Current Configuration</h3>
              </div>
              <div className="p-6">
                <pre className="bg-gray-50 p-4 rounded-md overflow-x-auto text-sm">
                  {JSON.stringify(config, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ManagementDashboard
