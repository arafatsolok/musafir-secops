import React, { useState, useEffect } from 'react'
import { 
  AlertTriangle, 
  Clock, 
  Users, 
  FileText, 
  CheckCircle, 
  XCircle, 
  Play, 
  Edit,
  Plus,
  Server
} from 'lucide-react'
import { incidentService, Incident as ApiIncident, CreateIncidentRequest } from '../services'

interface Incident {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
  assignee: string
  created: string
  updated: string
  description: string
  affected_assets: string[]
  tags: string[]
}

interface PlaybookStep {
  id: string
  title: string
  description: string
  status: 'pending' | 'in_progress' | 'completed' | 'skipped'
  assignee?: string
  estimated_time: string
  actual_time?: string
}

interface Playbook {
  id: string
  name: string
  description: string
  steps: PlaybookStep[]
  incident_types: string[]
}

const IncidentResponse: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'incidents' | 'playbooks' | 'timeline'>('incidents')
  const [selectedIncident, setSelectedIncident] = useState<string | null>(null)
  const [showNewIncident, setShowNewIncident] = useState(false)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [newIncidentForm, setNewIncidentForm] = useState({
    title: '',
    severity: 'medium' as 'critical' | 'high' | 'medium' | 'low',
    description: ''
  })

  // Load incidents on component mount
  useEffect(() => {
    loadIncidents()
  }, [])

  const loadIncidents = async () => {
    try {
      const response = await incidentService.getIncidents()
      
      if (response.success && response.data) {
        // Transform API data to match local Incident interface
        const transformedIncidents: Incident[] = response.data.map((apiIncident: ApiIncident) => ({
          id: apiIncident.id,
          title: apiIncident.title,
          severity: apiIncident.severity,
          status: apiIncident.status,
          assignee: apiIncident.assignedTo || '',
          created: apiIncident.createdAt,
          updated: apiIncident.updatedAt,
          description: apiIncident.description,
          affected_assets: apiIncident.affectedAssets,
          tags: apiIncident.tags
        }))
        setIncidents(transformedIncidents)
      } else {
        // Fallback to demo data if API is not available
        setIncidents([
          {
            id: '1',
            title: 'Ransomware Detection on Critical Server',
            severity: 'critical',
            status: 'investigating',
            assignee: 'John Smith',
            created: '2024-01-15T14:30:00Z',
            updated: '2024-01-15T15:45:00Z',
            description: 'Suspicious file encryption activity detected on production database server',
            affected_assets: ['DB-PROD-01', 'WEB-PROD-02'],
            tags: ['ransomware', 'malware', 'production']
          },
          {
            id: '2',
            title: 'Suspicious Login Activity',
            severity: 'high',
            status: 'contained',
            assignee: 'Sarah Johnson',
            created: '2024-01-15T12:15:00Z',
            updated: '2024-01-15T14:20:00Z',
            description: 'Multiple failed login attempts followed by successful login from unusual location',
            affected_assets: ['AD-DC-01'],
            tags: ['authentication', 'brute-force']
          },
          {
            id: '3',
            title: 'Data Exfiltration Attempt',
            severity: 'medium',
            status: 'resolved',
            assignee: 'Mike Wilson',
            created: '2024-01-14T16:45:00Z',
            updated: '2024-01-15T09:30:00Z',
            description: 'Unusual outbound network traffic detected from finance workstation',
            affected_assets: ['WS-FIN-05'],
            tags: ['data-exfiltration', 'network']
          }
        ])
      }
    } catch (err) {
      console.error('Error loading incidents:', err)
    }
  }

  const handleCreateIncident = async (incidentData: CreateIncidentRequest) => {
    try {
      const response = await incidentService.createIncident(incidentData)
      
      if (response.success && response.data) {
        // Transform API response to match local Incident interface
        const transformedIncident: Incident = {
          id: response.data.id,
          title: response.data.title,
          severity: response.data.severity,
          status: response.data.status,
          assignee: response.data.assignedTo || '',
          created: response.data.createdAt,
          updated: response.data.updatedAt,
          description: response.data.description,
          affected_assets: response.data.affectedAssets,
          tags: response.data.tags
        }
        setIncidents(prev => [transformedIncident, ...prev])
        setShowNewIncident(false)
        setNewIncidentForm({ title: '', severity: 'medium', description: '' })
      } else {
        console.error('Failed to create incident:', response.error)
      }
    } catch (err) {
      console.error('Error creating incident:', err)
    }
  }

  const handleSubmitNewIncident = async (e: React.FormEvent) => {
    e.preventDefault()
    
    const incidentData: CreateIncidentRequest = {
      title: newIncidentForm.title,
      severity: newIncidentForm.severity,
      description: newIncidentForm.description,
      affectedAssets: [],
      tags: []
    }
    
    await handleCreateIncident(incidentData)
  }

  const [playbooks] = useState<Playbook[]>([
    {
      id: '1',
      name: 'Ransomware Response',
      description: 'Standard response procedure for ransomware incidents',
      incident_types: ['ransomware', 'malware'],
      steps: [
        {
          id: '1',
          title: 'Isolate Affected Systems',
          description: 'Immediately disconnect affected systems from the network',
          status: 'completed',
          assignee: 'John Smith',
          estimated_time: '15 min',
          actual_time: '12 min'
        },
        {
          id: '2',
          title: 'Assess Scope of Impact',
          description: 'Determine which systems and data are affected',
          status: 'in_progress',
          assignee: 'John Smith',
          estimated_time: '30 min'
        },
        {
          id: '3',
          title: 'Notify Stakeholders',
          description: 'Inform management and relevant teams about the incident',
          status: 'pending',
          estimated_time: '10 min'
        },
        {
          id: '4',
          title: 'Begin Recovery Process',
          description: 'Start system restoration from clean backups',
          status: 'pending',
          estimated_time: '2 hours'
        }
      ]
    }
  ])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-700 bg-red-100 border-red-200'
      case 'high':
        return 'text-orange-700 bg-orange-100 border-orange-200'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      case 'low':
        return 'text-green-700 bg-green-100 border-green-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open':
        return 'text-red-600 bg-red-100'
      case 'investigating':
        return 'text-blue-600 bg-blue-100'
      case 'contained':
        return 'text-yellow-600 bg-yellow-100'
      case 'resolved':
        return 'text-green-600 bg-green-100'
      case 'closed':
        return 'text-gray-600 bg-gray-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const getStepStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'in_progress':
        return <Clock className="h-5 w-5 text-blue-500" />
      case 'skipped':
        return <XCircle className="h-5 w-5 text-gray-500" />
      default:
        return <div className="h-5 w-5 rounded-full border-2 border-gray-300" />
    }
  }

  const selectedIncidentData = incidents.find(inc => inc.id === selectedIncident)
  const activePlaybook = selectedIncidentData ? playbooks.find(pb => 
    pb.incident_types.some(type => selectedIncidentData.tags.includes(type))
  ) : null

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Incident Response</h1>
            <p className="text-gray-600">Coordinate and manage security incident response</p>
          </div>
          <button
            onClick={() => setShowNewIncident(true)}
            className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
          >
            <Plus className="h-4 w-4" />
            <span>New Incident</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'incidents', label: 'Active Incidents', icon: AlertTriangle },
            { id: 'playbooks', label: 'Response Playbooks', icon: FileText },
            { id: 'timeline', label: 'Timeline & Notes', icon: Clock }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-red-500 text-red-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="h-5 w-5" />
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Incidents Tab */}
      {activeTab === 'incidents' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Incidents List */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-sm">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Security Incidents</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {incidents.map((incident) => (
                  <div
                    key={incident.id}
                    onClick={() => setSelectedIncident(incident.id)}
                    className={`p-6 cursor-pointer hover:bg-gray-50 transition-colors ${
                      selectedIncident === incident.id ? 'bg-blue-50 border-l-4 border-blue-500' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <h4 className="text-lg font-medium text-gray-900">{incident.title}</h4>
                      <div className="flex space-x-2">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(incident.severity)}`}>
                          {incident.severity.toUpperCase()}
                        </span>
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(incident.status)}`}>
                          {incident.status.replace('_', ' ').toUpperCase()}
                        </span>
                      </div>
                    </div>
                    <p className="text-gray-600 mb-3">{incident.description}</p>
                    <div className="flex items-center justify-between text-sm text-gray-500">
                      <div className="flex items-center space-x-4">
                        <span>Assignee: {incident.assignee}</span>
                        <span>Assets: {incident.affected_assets.length}</span>
                      </div>
                      <span>{new Date(incident.created).toLocaleString()}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {incident.tags.map((tag, index) => (
                        <span key={index} className="inline-flex px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Incident Details */}
          <div>
            {selectedIncidentData ? (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">Incident Details</h3>
                  <button className="text-gray-400 hover:text-gray-600">
                    <Edit className="h-4 w-4" />
                  </button>
                </div>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                    <select className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                      <option value={selectedIncidentData.status}>{selectedIncidentData.status}</option>
                      <option value="investigating">Investigating</option>
                      <option value="contained">Contained</option>
                      <option value="resolved">Resolved</option>
                    </select>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Assignee</label>
                    <input
                      type="text"
                      value={selectedIncidentData.assignee}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      readOnly
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Affected Assets</label>
                    <div className="space-y-1">
                      {selectedIncidentData.affected_assets.map((asset, index) => (
                        <div key={index} className="flex items-center space-x-2">
                          <Server className="h-4 w-4 text-gray-400" />
                          <span className="text-sm text-gray-900">{asset}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Timeline</label>
                    <div className="text-sm text-gray-600 space-y-1">
                      <div>Created: {new Date(selectedIncidentData.created).toLocaleString()}</div>
                      <div>Updated: {new Date(selectedIncidentData.updated).toLocaleString()}</div>
                    </div>
                  </div>
                </div>
                
                <div className="mt-6 pt-4 border-t border-gray-200">
                  <button className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                    <Play className="h-4 w-4" />
                    <span>Execute Playbook</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow-sm p-6 text-center text-gray-500">
                <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>Select an incident to view details</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Playbooks Tab */}
      {activeTab === 'playbooks' && (
        <div className="space-y-6">
          {selectedIncidentData && activePlaybook && (
            <div className="bg-white rounded-lg shadow-sm p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{activePlaybook.name}</h3>
                  <p className="text-gray-600">{activePlaybook.description}</p>
                </div>
                <div className="text-sm text-gray-500">
                  For incident: {selectedIncidentData.title}
                </div>
              </div>
              
              <div className="space-y-4">
                {activePlaybook.steps.map((step) => (
                  <div key={step.id} className="flex items-start space-x-4 p-4 border border-gray-200 rounded-lg">
                    <div className="flex-shrink-0 mt-1">
                      {getStepStatusIcon(step.status)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-gray-900">{step.title}</h4>
                        <div className="flex items-center space-x-2 text-sm text-gray-500">
                          <Clock className="h-4 w-4" />
                          <span>{step.actual_time || step.estimated_time}</span>
                        </div>
                      </div>
                      <p className="text-gray-600 mb-2">{step.description}</p>
                      {step.assignee && (
                        <div className="flex items-center space-x-2 text-sm text-gray-500">
                          <Users className="h-4 w-4" />
                          <span>{step.assignee}</span>
                        </div>
                      )}
                    </div>
                    <div className="flex space-x-2">
                      {step.status === 'pending' && (
                        <button className="text-blue-600 hover:text-blue-800">
                          <Play className="h-4 w-4" />
                        </button>
                      )}
                      {step.status === 'in_progress' && (
                        <button className="text-green-600 hover:text-green-800">
                          <CheckCircle className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {!selectedIncidentData && (
            <div className="bg-white rounded-lg shadow-sm p-6 text-center text-gray-500">
              <FileText className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>Select an incident to view available playbooks</p>
            </div>
          )}
        </div>
      )}

      {/* Timeline Tab */}
      {activeTab === 'timeline' && (
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-6">Incident Timeline</h3>
          {selectedIncidentData ? (
            <div className="space-y-6">
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-2 h-2 bg-red-500 rounded-full mt-2"></div>
                <div>
                  <div className="text-sm font-medium text-gray-900">Incident Created</div>
                  <div className="text-sm text-gray-500">{new Date(selectedIncidentData.created).toLocaleString()}</div>
                  <div className="text-sm text-gray-600 mt-1">{selectedIncidentData.description}</div>
                </div>
              </div>
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                <div>
                  <div className="text-sm font-medium text-gray-900">Investigation Started</div>
                  <div className="text-sm text-gray-500">{new Date(selectedIncidentData.updated).toLocaleString()}</div>
                  <div className="text-sm text-gray-600 mt-1">Assigned to {selectedIncidentData.assignee}</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-gray-500">
              <Clock className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>Select an incident to view timeline</p>
            </div>
          )}
        </div>
      )}

      {/* New Incident Modal */}
      {showNewIncident && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Create New Incident</h3>
              <button
                onClick={() => setShowNewIncident(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XCircle className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleSubmitNewIncident} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
                <input
                  type="text"
                  value={newIncidentForm.title}
                  onChange={(e) => setNewIncidentForm(prev => ({ ...prev, title: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Enter incident title"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select 
                  value={newIncidentForm.severity}
                  onChange={(e) => setNewIncidentForm(prev => ({ ...prev, severity: e.target.value as 'critical' | 'high' | 'medium' | 'low' }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={newIncidentForm.description}
                  onChange={(e) => setNewIncidentForm(prev => ({ ...prev, description: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500"
                  placeholder="Describe the incident"
                  required
                />
              </div>
              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowNewIncident(false)}
                  className="px-4 py-2 text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
                >
                  Create Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default IncidentResponse