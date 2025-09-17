import React, { useState, useEffect } from 'react'
import { 
  Layout, 
  Monitor, 
  BarChart3, 
  Search, 
  Network, 
  Database, 
  MessageSquare, 
  HardDrive,
  Settings,
  ExternalLink,
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Activity,
  Globe,
  Shield,
  Zap
} from 'lucide-react'

interface ServiceStatus {
  name: string
  url: string
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown'
  description: string
  icon: React.ReactNode
  credentials?: string
  category: 'monitoring' | 'database' | 'management' | 'storage'
}

interface GatewayMetrics {
  request_count: number
  error_count: number
  avg_response_time: number
  active_connections: number
  last_updated: string | Date
}

const CentralPortal: React.FC = () => {
  const [services, setServices] = useState<ServiceStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [liveMetrics, setLiveMetrics] = useState<GatewayMetrics | null>(null)
  const [wsConnected, setWsConnected] = useState(false)

  useEffect(() => {
    initializeServices()
    checkServiceStatus()
    connectWebSocket()
    
    // Check status every 30 seconds
    const interval = setInterval(checkServiceStatus, 30000)
    return () => {
      clearInterval(interval)
    }
  }, [])

  const initializeServices = () => {
    const serviceList: ServiceStatus[] = [
      {
        name: 'Main Dashboard',
        url: 'http://localhost:3000',
        status: 'unknown',
        description: 'Primary MUSAFIR SecOps interface with real-time events, query workbench, and service management',
        icon: <Shield className="h-6 w-6" />,
        category: 'management'
      },
      {
        name: 'Grafana',
        url: 'http://localhost:3001',
        status: 'unknown',
        description: 'Advanced monitoring dashboards with customizable visualizations and alerting',
        icon: <BarChart3 className="h-6 w-6" />,
        credentials: 'admin/admin',
        category: 'monitoring'
      },
      {
        name: 'Prometheus',
        url: 'http://localhost:9090',
        status: 'unknown',
        description: 'Metrics collection and storage for system and application monitoring',
        icon: <Activity className="h-6 w-6" />,
        category: 'monitoring'
      },
      {
        name: 'Jaeger',
        url: 'http://localhost:16686',
        status: 'unknown',
        description: 'Distributed tracing for request flow analysis and performance monitoring',
        icon: <Network className="h-6 w-6" />,
        category: 'monitoring'
      },
      {
        name: 'Neo4j Browser',
        url: 'http://localhost:7474',
        status: 'unknown',
        description: 'Graph database browser for relationship analysis and network visualization',
        icon: <Globe className="h-6 w-6" />,
        credentials: 'neo4j/Strong@!@#bdnews24#',
        category: 'database'
      },
      {
        name: 'RabbitMQ Management',
        url: 'http://localhost:15672',
        status: 'unknown',
        description: 'Message queue management interface for monitoring and configuring queues',
        icon: <MessageSquare className="h-6 w-6" />,
        credentials: 'musafir/Strong@!@#bdnews24#',
        category: 'management'
      },
      {
        name: 'MinIO Console',
        url: 'http://localhost:9002',
        status: 'unknown',
        description: 'Object storage management for files, artifacts, and forensic data',
        icon: <HardDrive className="h-6 w-6" />,
        credentials: 'musafir/Strong@!@#bdnews24#',
        category: 'storage'
      }
    ]
    setServices(serviceList)
  }

  const connectWebSocket = () => {
    try {
      const ws = new WebSocket('ws://localhost:8080/ws')
      ws.onopen = () => setWsConnected(true)
      ws.onclose = () => setWsConnected(false)
      ws.onerror = () => setWsConnected(false)
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data)
          if (msg?.Type === 'metrics' || msg?.type === 'metrics') {
            setLiveMetrics(msg.Data || msg.data)
          }
        } catch (e) {}
      }
    } catch (e) {
      setWsConnected(false)
    }
  }

  const checkServiceStatus = async () => {
    const updatedServices = await Promise.all(
      services.map(async (service) => {
        try {
          const response = await fetch(service.url, { 
            method: 'HEAD',
            mode: 'no-cors',
            cache: 'no-cache'
          })
          return { ...service, status: 'healthy' as const }
        } catch (error) {
          // Try alternative check for services that don't support HEAD
          try {
            const response = await fetch(service.url, { 
              method: 'GET',
              mode: 'no-cors',
              cache: 'no-cache'
            })
            return { ...service, status: 'healthy' as const }
          } catch (error) {
            return { ...service, status: 'unhealthy' as const }
          }
        }
      })
    )
    setServices(updatedServices)
    setLoading(false)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'degraded': return <AlertTriangle className="h-5 w-5 text-yellow-500" />
      case 'unhealthy': return <XCircle className="h-5 w-5 text-red-500" />
      default: return <RefreshCw className="h-5 w-5 text-gray-400 animate-spin" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'border-green-200 bg-green-50'
      case 'degraded': return 'border-yellow-200 bg-yellow-50'
      case 'unhealthy': return 'border-red-200 bg-red-50'
      default: return 'border-gray-200 bg-gray-50'
    }
  }

  const filteredServices = services.filter(service => {
    const matchesCategory = selectedCategory === 'all' || service.category === selectedCategory
    const matchesSearch = service.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         service.description.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesCategory && matchesSearch
  })

  const categories = [
    { id: 'all', name: 'All Services', icon: <Settings className="h-4 w-4" /> },
    { id: 'management', name: 'Management', icon: <Shield className="h-4 w-4" /> },
    { id: 'monitoring', name: 'Monitoring', icon: <Monitor className="h-4 w-4" /> },
    { id: 'database', name: 'Databases', icon: <Database className="h-4 w-4" /> },
    { id: 'storage', name: 'Storage', icon: <HardDrive className="h-4 w-4" /> }
  ]

  const healthyCount = services.filter(s => s.status === 'healthy').length
  const totalCount = services.length

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-3">
              <Zap className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">MUSAFIR Central Portal</h1>
                <p className="text-sm text-gray-600">Unified access to all platform services</p>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              {/* Live metrics pill */}
              <div className="hidden md:flex items-center space-x-3">
                <div className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-gray-400'}`}></div>
                <div className="text-xs text-gray-600">
                  WS {wsConnected ? 'connected' : 'disconnected'}
                  {liveMetrics && (
                    <span className="ml-2">
                      • req: {liveMetrics.request_count || 0}
                      • err: {liveMetrics.error_count || 0}
                      • rt: {(liveMetrics.avg_response_time || 0).toFixed ? (liveMetrics.avg_response_time as number).toFixed(2) : liveMetrics.avg_response_time}s
                    </span>
                  )}
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm text-gray-600">System Status</div>
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${healthyCount === totalCount ? 'bg-green-500' : healthyCount > 0 ? 'bg-yellow-500' : 'bg-red-500'}`}></div>
                  <span className="text-sm font-medium">
                    {healthyCount}/{totalCount} Services Online
                  </span>
                </div>
              </div>
              <button
                onClick={checkServiceStatus}
                className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
                title="Refresh Status"
              >
                <RefreshCw className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Search and Filter */}
        <div className="mb-8">
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Search */}
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search services..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>

            {/* Category Filter */}
            <div className="flex space-x-2">
              {categories.map((category) => (
                <button
                  key={category.id}
                  onClick={() => setSelectedCategory(category.id)}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                    selectedCategory === category.id
                      ? 'bg-blue-100 text-blue-700 border border-blue-200'
                      : 'bg-white text-gray-700 border border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  {category.icon}
                  <span className="text-sm font-medium">{category.name}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Services Grid */}
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <RefreshCw className="h-8 w-8 animate-spin text-blue-600" />
            <span className="ml-2 text-gray-600">Checking service status...</span>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredServices.map((service, index) => (
              <div
                key={index}
                className={`rounded-lg border-2 p-6 transition-all hover:shadow-lg ${getStatusColor(service.status)}`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 bg-white rounded-lg shadow-sm">
                      {service.icon}
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">{service.name}</h3>
                      <div className="flex items-center space-x-2 mt-1">
                        {getStatusIcon(service.status)}
                        <span className="text-sm text-gray-600 capitalize">{service.status}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <p className="text-sm text-gray-600 mb-4">{service.description}</p>

                {service.credentials && (
                  <div className="mb-4 p-3 bg-gray-100 rounded-lg">
                    <div className="text-xs text-gray-500 mb-1">Credentials:</div>
                    <div className="text-sm font-mono text-gray-700">{service.credentials}</div>
                  </div>
                )}

                <div className="flex items-center justify-between">
                  <a
                    href={service.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 text-blue-600 hover:text-blue-700 transition-colors"
                  >
                    <span className="text-sm font-medium">Open Service</span>
                    <ExternalLink className="h-4 w-4" />
                  </a>
                  <div className="text-xs text-gray-500">
                    {service.url.replace('http://localhost:', '')}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Quick Actions */}
        <div className="mt-12 bg-white rounded-lg shadow-sm border p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <button
              onClick={checkServiceStatus}
              className="flex items-center space-x-2 p-3 text-left border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <RefreshCw className="h-5 w-5 text-blue-600" />
              <span className="text-sm font-medium">Refresh All Status</span>
            </button>
            <a
              href="http://localhost:3000"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 p-3 text-left border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <Shield className="h-5 w-5 text-green-600" />
              <span className="text-sm font-medium">Open Main Dashboard</span>
            </a>
            <a
              href="http://localhost:3001"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 p-3 text-left border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <BarChart3 className="h-5 w-5 text-purple-600" />
              <span className="text-sm font-medium">Open Grafana</span>
            </a>
            <a
              href="http://localhost:9090"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 p-3 text-left border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
            >
              <Activity className="h-5 w-5 text-orange-600" />
              <span className="text-sm font-medium">Open Prometheus</span>
            </a>
          </div>
        </div>

        {/* System Information */}
        <div className="mt-8 bg-white rounded-lg shadow-sm border p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">System Information</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            <div>
              <div className="text-sm text-gray-600 mb-1">Platform</div>
              <div className="text-lg font-semibold text-gray-900">MUSAFIR SecOps</div>
            </div>
            <div>
              <div className="text-sm text-gray-600 mb-1">Services</div>
              <div className="text-lg font-semibold text-gray-900">{totalCount} Total</div>
            </div>
            <div>
              <div className="text-sm text-gray-600 mb-1">Status</div>
              <div className="text-lg font-semibold text-gray-900">
                {healthyCount === totalCount ? 'All Online' : `${healthyCount} Online`}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CentralPortal
