import React, { useState, useEffect } from 'react'
import { 
  Search, 
  Target, 
  Filter, 
  Download, 
  Play, 
  Save, 
  AlertTriangle,
  Eye,
  FileText,
  Shield
} from 'lucide-react'
import { incidentService, vulnerabilityService } from '../services'
import { useApp } from '../contexts/AppContext'

interface ThreatHunt {
  id: string
  name: string
  query: string
  status: 'running' | 'completed' | 'failed'
  results: number
  created: string
  duration: string
}

interface IOCIndicator {
  type: 'ip' | 'domain' | 'hash' | 'url'
  value: string
  threat_level: 'high' | 'medium' | 'low'
  first_seen: string
  last_seen: string
  sources: string[]
}

const ThreatHunting: React.FC = () => {
  const { } = useApp();
  const [activeTab, setActiveTab] = useState<'hunt' | 'ioc' | 'results'>('hunt')
  const [huntQuery, setHuntQuery] = useState('')
  const [iocSearch, setIocSearch] = useState('')
  const [savedHunts, setSavedHunts] = useState<ThreatHunt[]>([])
  const [iocIndicators, setIocIndicators] = useState<IOCIndicator[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // const [isRunningHunt, setIsRunningHunt] = useState(false)
  // const [huntResults, setHuntResults] = useState<any[]>([])

  // Event handlers
  // const handleRunHunt = async () => {
  //   if (!huntQuery.trim()) {
  //     showWarning('Invalid Query', 'Please enter a hunt query before running.');
  //     return;
  //   }

  //   setIsRunningHunt(true);
  //   try {
  //     // Simulate hunt execution
  //     await new Promise(resolve => setTimeout(resolve, 2000));
      
  //     // Mock results
  //     const mockResults = [
  //       { id: 1, timestamp: new Date().toISOString(), asset: 'SERVER-01', event: 'Suspicious process execution' },
  //       { id: 2, timestamp: new Date().toISOString(), asset: 'WORKSTATION-05', event: 'Unusual network connection' },
  //       { id: 3, timestamp: new Date().toISOString(), asset: 'SERVER-03', event: 'File modification detected' }
  //     ];
      
  //     setHuntResults(mockResults);
  //     showSuccess('Hunt Complete', `Hunt executed successfully. Found ${mockResults.length} results.`);
  //   } catch (error) {
  //     showError('Hunt Failed', 'Failed to execute threat hunt. Please try again.');
  //   } finally {
  //     setIsRunningHunt(false);
  //   }
  // };

  // const handleSaveHunt = () => {
  //   if (!huntQuery.trim()) {
  //     showWarning('Invalid Query', 'Please enter a hunt query before saving.');
  //     return;
  //   }

  //   const newHunt: ThreatHunt = {
  //     id: Date.now().toString(),
  //     name: `Hunt ${savedHunts.length + 1}`,
  //     query: huntQuery,
  //     status: 'completed',
  //     results: huntResults.length,
  //     created: new Date().toISOString(),
  //     duration: '2.3s'
  //   };

  //   setSavedHunts(prev => [...prev, newHunt]);
  //   showSuccess('Hunt Saved', `Hunt "${newHunt.name}" has been saved successfully.`);
  // };

  // const handleDownloadResults = () => {
  //   if (huntResults.length === 0) {
  //     showWarning('No Results', 'No hunt results available to download.');
  //     return;
  //   }

  //   const dataStr = JSON.stringify(huntResults, null, 2);
  //   const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
  //   const url = URL.createObjectURL(dataBlob);
  //   const link = document.createElement('a');
  //   link.href = url;
  //   link.download = `hunt-results-${new Date().toISOString().split('T')[0]}.json`;
  //   document.body.appendChild(link);
  //   link.click();
  //   document.body.removeChild(link);
  //   URL.revokeObjectURL(url);

  //   showSuccess('Download Complete', `Downloaded ${huntResults.length} hunt results.`);
  // };

  // const handleRefresh = useCallback(async () => {
  //   setLoading(true);
  //   try {
  //     await loadThreatData();
  //     showSuccess('Data Refreshed', 'Threat hunting data has been refreshed successfully.');
  //   } catch (error) {
  //     console.error('Error refreshing data:', error);
  //     showError('Refresh Failed', 'Failed to refresh threat data. Please try again.');
  //   } finally {
  //     setLoading(false);
  //   }
  // }, []);

  useEffect(() => {
    loadThreatData()
  }, [])

  const loadThreatData = async () => {
    try {
      setLoading(true)
      
      // Load threat hunting data - using incident service as proxy
      const incidentResponse = await incidentService.getIncidents()
      
      if (incidentResponse.success && incidentResponse.data) {
        // Convert incidents to threat hunts for demo
        const hunts: ThreatHunt[] = incidentResponse.data.slice(0, 3).map((incident) => ({
          id: incident.id,
          name: `Hunt: ${incident.title}`,
          query: `event.name:"security_incident" AND severity:"${incident.severity}"`,
          status: incident.status === 'open' ? 'running' : 'completed' as 'running' | 'completed',
          results: Math.floor(Math.random() * 500) + 50,
          created: incident.createdAt,
          duration: `${Math.floor(Math.random() * 10) + 1}.${Math.floor(Math.random() * 9)}s`
        }))
        setSavedHunts(hunts)
      } else {
        // Fallback to demo data
        setSavedHunts([
          {
            id: '1',
            name: 'PowerShell Execution Analysis',
            query: 'event.name:"process_create" AND process.command_line:*powershell*',
            status: 'completed',
            results: 247,
            created: '2024-01-15 14:30',
            duration: '2.3s'
          },
          {
            id: '2',
            name: 'Suspicious Network Connections',
            query: 'event.name:"network_connect" AND destination.port:(4444 OR 5555 OR 6666)',
            status: 'running',
            results: 0,
            created: '2024-01-15 15:45',
            duration: '45s'
          }
        ])
      }

      // Load IOC indicators - using vulnerability service as proxy
      const vulnResponse = await vulnerabilityService.getVulnerabilities()
      
      if (vulnResponse.success && vulnResponse.data) {
        // Convert vulnerabilities to IOC indicators for demo
        const indicators: IOCIndicator[] = vulnResponse.data.slice(0, 5).map((vuln, index) => ({
          type: ['ip', 'domain', 'hash', 'url'][index % 4] as 'ip' | 'domain' | 'hash' | 'url',
          value: vuln.id.includes('CVE') ? `192.168.1.${100 + index}` : vuln.id,
          threat_level: vuln.severity as 'high' | 'medium' | 'low',
          first_seen: vuln.discoveredAt,
          last_seen: vuln.discoveredAt,
          sources: ['Internal', 'VirusTotal', 'MISP']
        }))
        setIocIndicators(indicators)
      } else {
        // Fallback to demo IOC data
        setIocIndicators([
          {
            type: 'ip',
            value: '192.168.1.100',
            threat_level: 'high',
            first_seen: '2024-01-15 10:00',
            last_seen: '2024-01-15 14:30',
            sources: ['Internal', 'VirusTotal']
          },
          {
            type: 'domain',
            value: 'malicious-site.com',
            threat_level: 'medium',
            first_seen: '2024-01-14 16:20',
            last_seen: '2024-01-15 12:15',
            sources: ['MISP', 'ThreatConnect']
          }
        ])
      }
    } catch (err) {
      console.error('Error loading threat data:', err)
      setError('Failed to load threat hunting data')
    } finally {
      setLoading(false)
    }
  }

  const [huntTemplates] = useState([
    {
      name: 'Lateral Movement Detection',
      query: 'event.name:"logon" AND logon.type:"network" AND user.name:*admin*',
      description: 'Detect potential lateral movement using admin accounts'
    },
    {
      name: 'Persistence Mechanisms',
      query: 'event.name:"registry_set" AND registry.path:*\\Run\\*',
      description: 'Find registry-based persistence mechanisms'
    },
    {
      name: 'Data Exfiltration',
      query: 'event.name:"file_access" AND file.size:>10MB AND network.bytes_out:>100MB',
      description: 'Identify potential data exfiltration activities'
    }
  ])

  const executeHunt = () => {
    if (!huntQuery.trim()) return
    
    const newHunt: ThreatHunt = {
      id: Date.now().toString(),
      name: `Hunt ${savedHunts.length + 1}`,
      query: huntQuery,
      status: 'running',
      results: 0,
      created: new Date().toLocaleString(),
      duration: '0s'
    }
    
    setSavedHunts([newHunt, ...savedHunts])
    
    // Simulate hunt execution
    setTimeout(() => {
      setSavedHunts(prev => prev.map(hunt => 
        hunt.id === newHunt.id 
          ? { ...hunt, status: 'completed', results: Math.floor(Math.random() * 500), duration: '3.2s' }
          : hunt
      ))
    }, 3000)
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'text-blue-600 bg-blue-100'
      case 'completed':
        return 'text-green-600 bg-green-100'
      case 'failed':
        return 'text-red-600 bg-red-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'high':
        return 'text-red-600 bg-red-100'
      case 'medium':
        return 'text-yellow-600 bg-yellow-100'
      case 'low':
        return 'text-green-600 bg-green-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  if (loading) {
    return (
      <div className="p-6 bg-gray-50 min-h-full">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <Target className="h-8 w-8 text-blue-600 animate-spin mx-auto mb-4" />
            <p className="text-gray-600">Loading threat hunting data...</p>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 bg-gray-50 min-h-full">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <AlertTriangle className="h-8 w-8 text-red-600 mx-auto mb-4" />
            <p className="text-red-600 mb-2">Error loading threat hunting data</p>
            <p className="text-gray-600 text-sm">{error}</p>
            <button 
              onClick={loadThreatData}
              className="mt-4 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Threat Hunting</h1>
        <p className="text-gray-600">Proactive threat detection and analysis</p>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'hunt', label: 'Hunt Console', icon: Target },
            { id: 'ioc', label: 'IOC Analysis', icon: Shield },
            { id: 'results', label: 'Hunt Results', icon: FileText }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-5 w-5" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Hunt Console Tab */}
      {activeTab === 'hunt' && (
        <div className="space-y-6">
          {/* Query Builder */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Query Builder</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Hunt Query
                </label>
                <textarea
                  value={huntQuery}
                  onChange={(e) => setHuntQuery(e.target.value)}
                  placeholder="Enter your threat hunting query (e.g., event.name:&quot;process_create&quot; AND process.name:*powershell*)"
                  className="w-full h-32 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                />
              </div>
              <div className="flex items-center space-x-4">
                <button
                  onClick={executeHunt}
                  className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                >
                  <Play className="h-4 w-4" />
                  <span>Execute Hunt</span>
                </button>
                <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
                  <Save className="h-4 w-4" />
                  <span>Save Query</span>
                </button>
                <button className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
                  <Filter className="h-4 w-4" />
                  <span>Add Filters</span>
                </button>
              </div>
            </div>
          </div>

          {/* Hunt Templates */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Hunt Templates</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {huntTemplates.map((template, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors cursor-pointer">
                  <h4 className="font-medium text-gray-900 mb-2">{template.name}</h4>
                  <p className="text-sm text-gray-600 mb-3">{template.description}</p>
                  <button
                    onClick={() => setHuntQuery(template.query)}
                    className="text-sm text-blue-600 hover:text-blue-800 font-medium"
                  >
                    Use Template
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* IOC Analysis Tab */}
      {activeTab === 'ioc' && (
        <div className="space-y-6">
          {/* IOC Search */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">IOC Search</h3>
            <div className="flex space-x-4">
              <div className="flex-1">
                <input
                  type="text"
                  value={iocSearch}
                  onChange={(e) => setIocSearch(e.target.value)}
                  placeholder="Enter IP, domain, hash, or URL to search..."
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <button className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                <Search className="h-4 w-4" />
                <span>Search</span>
              </button>
            </div>
          </div>

          {/* IOC Results */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Threat Indicators</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Indicator
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Threat Level
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      First Seen
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Sources
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {iocIndicators.map((ioc, index) => (
                    <tr key={index} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-800">
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap font-mono text-sm text-gray-900">
                        {ioc.value}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getThreatLevelColor(ioc.threat_level)}`}>
                          {ioc.threat_level.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {ioc.first_seen}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {ioc.sources.join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Hunt Results Tab */}
      {activeTab === 'results' && (
        <div className="space-y-6">
          {/* Active Hunts */}
          <div className="bg-white rounded-lg shadow-sm">
            <div className="px-6 py-4 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900">Hunt History</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Hunt Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Results
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Duration
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {savedHunts.map((hunt) => (
                    <tr key={hunt.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-gray-900">{hunt.name}</div>
                        <div className="text-sm text-gray-500 font-mono truncate max-w-xs">{hunt.query}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(hunt.status)}`}>
                          {hunt.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {hunt.results.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {hunt.duration}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {hunt.created}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex space-x-2">
                          <button className="text-blue-600 hover:text-blue-900">
                            <Eye className="h-4 w-4" />
                          </button>
                          <button className="text-green-600 hover:text-green-900">
                            <Download className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ThreatHunting