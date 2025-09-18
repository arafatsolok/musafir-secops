import React, { useState, useEffect } from 'react'
import { 
  Search, 
  FileText, 
  HardDrive, 
  Network, 
  Clock, 
  Eye, 
  Download, 
  Database,
  Cpu,
  Hash,
  User,
  Plus,
  Play
} from 'lucide-react'
import { forensicsService } from '../services'
import type { Evidence } from '../services/forensics'

// Local interfaces for types not in api.ts
interface Artifact {
  id: string
  evidence_id: string
  type: string
  description: string
  timestamp: string
  relevance: 'high' | 'medium' | 'low'
  tags: string[]
}

interface TimelineEvent {
  id: string
  timestamp: string
  event_type: string
  description: string
  source: string
  confidence: 'high' | 'medium' | 'low'
}

// Local ForensicCase interface to match component needs
interface ForensicCase {
  id: string
  name: string
  description: string
  status: 'active' | 'completed' | 'on_hold'
  priority: 'low' | 'medium' | 'high' | 'critical'
  investigator: string
  created: string
  updated: string
  evidence_count: number
  artifacts_count: number
}

const ForensicsLab: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'cases' | 'evidence' | 'analysis' | 'timeline' | 'reports'>('cases')
  const [selectedCase, setSelectedCase] = useState<string | null>(null)
  const [cases, setCases] = useState<ForensicCase[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([])
  const [showNewCase, setShowNewCase] = useState(false)
  const [showNewEvidence, setShowNewEvidence] = useState(false)
  const [newCaseForm, setNewCaseForm] = useState({
    name: '',
    description: '',
    priority: 'medium' as 'low' | 'medium' | 'high' | 'critical',
    investigator: ''
  })
  const [newEvidenceForm, setNewEvidenceForm] = useState({
    name: '',
    type: 'disk_image' as 'disk_image' | 'memory_dump' | 'network_capture' | 'log_file' | 'registry' | 'file_system',
    source: '',
    hash: ''
  })

  useEffect(() => {
    loadCases()
  }, [])

  useEffect(() => {
    if (selectedCase) {
      loadEvidence(selectedCase)
      loadTimeline(selectedCase)
    }
  }, [selectedCase])

  const loadCases = async () => {
    try {
      const response = await forensicsService.getCases()
      
      if (response.success && response.data) {
        setCases(response.data)
      } else {
        // Fallback to demo data if API is not available
        setCases([
          {
            id: '1',
            name: 'Ransomware Investigation - Server Compromise',
            description: 'Investigation of ransomware attack on production servers',
            status: 'active',
            priority: 'critical',
            investigator: 'Dr. Sarah Chen',
            created: '2024-01-15 09:00:00',
            updated: '2024-01-15 15:30:00',
            evidence_count: 5,
            artifacts_count: 127
          },
          {
            id: '2',
            name: 'Data Exfiltration Analysis',
            description: 'Analysis of suspicious data transfer activities',
            status: 'active',
            priority: 'high',
            investigator: 'Mike Rodriguez',
            created: '2024-01-14 14:20:00',
            updated: '2024-01-15 11:45:00',
            evidence_count: 3,
            artifacts_count: 89
          },
          {
            id: '3',
            name: 'Insider Threat Investigation',
            description: 'Investigation of potential insider threat activities',
            status: 'completed',
            priority: 'medium',
            investigator: 'Lisa Wang',
            created: '2024-01-10 10:15:00',
            updated: '2024-01-13 16:30:00',
            evidence_count: 7,
            artifacts_count: 234
          }
        ])
      }
    } catch (err) {
      console.error('Error loading cases:', err)
    }
  }

  const loadEvidence = async (caseId: string) => {
    try {
      const response = await forensicsService.getEvidence(caseId)
      
      if (response.success && response.data) {
        setEvidence(response.data)
        // Load artifacts for all evidence
        const allArtifacts: Artifact[] = []
        for (const evidenceItem of response.data) {
          const artifactsResponse = await forensicsService.getArtifacts(evidenceItem.id)
          if (artifactsResponse.success && artifactsResponse.data) {
            allArtifacts.push(...artifactsResponse.data)
          }
        }
        setArtifacts(allArtifacts)
      } else {
        // Fallback to demo data
        setEvidence([
          {
            id: '1',
            case_id: caseId,
            name: 'Server-01-Disk-Image.dd',
            type: 'disk_image',
            size: '500000000000', // 500 GB in bytes as string
            hash: 'sha256:a1b2c3d4e5f6...',
            collected: '2024-01-15 10:30:00',
            source: 'Production Server DB-01',
            status: 'analyzed'
          }
        ])
        setArtifacts([
          {
            id: '1',
            evidence_id: '1',
            type: 'Malicious File',
            description: 'Ransomware executable found in system directory',
            timestamp: '2024-01-15 09:45:00',
            relevance: 'high',
            tags: ['malware', 'ransomware', 'executable']
          }
        ])
      }
    } catch (err) {
      console.error('Error loading evidence:', err)
    }
  }

  const loadTimeline = async (caseId: string) => {
    try {
      const response = await forensicsService.getTimeline(caseId)
      
      if (response.success && response.data) {
        setTimelineEvents(response.data)
      } else {
        // Fallback to demo data
        setTimelineEvents([
          {
            id: '1',
            timestamp: '2024-01-15 09:00:00',
            event_type: 'Initial Detection',
            description: 'Ransomware activity detected by EDR system',
            source: 'EDR Alert',
            confidence: 'high'
          }
        ])
      }
    } catch (err) {
      console.error('Error loading timeline:', err)
    }
  }

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      const response = await forensicsService.createCase(newCaseForm)
      
      if (response.success && response.data) {
        setCases(prev => [response.data!, ...prev])
        setShowNewCase(false)
        setNewCaseForm({ name: '', description: '', priority: 'medium', investigator: '' })
      } else {
        console.error('Failed to create case:', response.error)
      }
    } catch (err) {
      console.error('Error creating case:', err)
    }
  }

  const handleCreateEvidence = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!selectedCase) return
    
    try {
      const evidenceData = {
        ...newEvidenceForm,
        case_id: selectedCase
      }
      
      const response = await forensicsService.createEvidence(evidenceData)
      
      if (response.success && response.data) {
        setEvidence(prev => [response.data!, ...prev])
        setShowNewEvidence(false)
        setNewEvidenceForm({ name: '', type: 'disk_image', source: '', hash: '' })
        // Reload case to update evidence count
        loadCases()
      } else {
        console.error('Failed to create evidence:', response.error)
      }
    } catch (err) {
      console.error('Error creating evidence:', err)
    }
  }

  const handleStartAnalysis = async (caseId: string) => {
    try {
      const response = await forensicsService.startAnalysis(caseId, 'comprehensive')
      
      if (response.success && response.data) {
        console.log('Analysis started:', response.data.analysisId)
        // You could add a notification or update UI to show analysis is running
      } else {
        console.error('Failed to start analysis:', response.error)
      }
    } catch (err) {
      console.error('Error starting analysis:', err)
    }
  }

  const handleGenerateReport = async (caseId: string) => {
    try {
      const response = await forensicsService.generateReport(caseId, 'pdf')
      
      if (response.success && response.data) {
        // Open the report URL in a new tab
        window.open(response.data.reportUrl, '_blank')
      } else {
        console.error('Failed to generate report:', response.error)
      }
    } catch (err) {
      console.error('Error generating report:', err)
    }
  }

  const handleExportEvidence = async (evidenceId: string) => {
    try {
      const response = await forensicsService.exportEvidence(evidenceId, 'e01')
      
      if (response.success && response.data) {
        // Trigger download
        window.open(response.data.exportUrl, '_blank')
      } else {
        console.error('Failed to export evidence:', response.error)
      }
    } catch (err) {
      console.error('Error exporting evidence:', err)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-blue-700 bg-blue-100 border-blue-200'
      case 'completed':
        return 'text-green-700 bg-green-100 border-green-200'
      case 'on_hold':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200'
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200'
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical':
        return 'text-red-700 bg-red-100'
      case 'high':
        return 'text-orange-700 bg-orange-100'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100'
      case 'low':
        return 'text-green-700 bg-green-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const getEvidenceIcon = (type: string) => {
    switch (type) {
      case 'disk_image':
        return <HardDrive className="h-5 w-5 text-blue-600" />
      case 'memory_dump':
        return <Cpu className="h-5 w-5 text-purple-600" />
      case 'network_capture':
        return <Network className="h-5 w-5 text-green-600" />
      case 'log_file':
        return <FileText className="h-5 w-5 text-orange-600" />
      case 'registry':
        return <Database className="h-5 w-5 text-red-600" />
      default:
        return <FileText className="h-5 w-5 text-gray-600" />
    }
  }

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high':
        return 'text-green-700 bg-green-100'
      case 'medium':
        return 'text-yellow-700 bg-yellow-100'
      case 'low':
        return 'text-red-700 bg-red-100'
      default:
        return 'text-gray-700 bg-gray-100'
    }
  }

  const selectedCaseData = cases.find(c => c.id === selectedCase)
  const caseEvidence = evidence.filter(e => e.case_id === selectedCase)
  const caseArtifacts = artifacts.filter(a => caseEvidence.some(e => e.id === a.evidence_id))

  return (
    <>
      <div className="p-6 bg-gray-50 min-h-full">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">Digital Forensics Lab</h1>
            <p className="text-gray-600">Investigate security incidents and analyze digital evidence</p>
          </div>
          <div className="flex space-x-3">
             <button 
               onClick={() => setShowNewCase(true)}
               className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
             >
               <Plus className="h-4 w-4" />
               <span>New Investigation</span>
             </button>
             {selectedCase && (
               <button 
                 onClick={() => handleGenerateReport(selectedCase)}
                 className="flex items-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors"
               >
                 <Download className="h-4 w-4" />
                 <span>Export Report</span>
               </button>
             )}
           </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'cases', label: 'Cases', icon: FileText },
            { id: 'evidence', label: 'Evidence', icon: HardDrive },
            { id: 'analysis', label: 'Analysis', icon: Search },
            { id: 'timeline', label: 'Timeline', icon: Clock },
            { id: 'reports', label: 'Reports', icon: Download }
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

      {/* Cases Tab */}
      {activeTab === 'cases' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Cases List */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-sm">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Forensic Cases</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {cases.map((forensicCase) => (
                  <div
                    key={forensicCase.id}
                    onClick={() => setSelectedCase(forensicCase.id)}
                    className={`p-6 cursor-pointer hover:bg-gray-50 transition-colors ${
                      selectedCase === forensicCase.id ? 'bg-blue-50 border-l-4 border-blue-500' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <h4 className="text-lg font-medium text-gray-900">{forensicCase.name}</h4>
                      <div className="flex space-x-2">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getPriorityColor(forensicCase.priority)}`}>
                          {forensicCase.priority.toUpperCase()}
                        </span>
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(forensicCase.status)}`}>
                          {forensicCase.status.replace('_', ' ').toUpperCase()}
                        </span>
                      </div>
                    </div>
                    <p className="text-gray-600 mb-3">{forensicCase.description}</p>
                    <div className="flex items-center justify-between text-sm text-gray-500">
                      <div className="flex items-center space-x-4">
                        <span>Investigator: {forensicCase.investigator}</span>
                        <span>Evidence: {forensicCase.evidence_count}</span>
                        <span>Artifacts: {forensicCase.artifacts_count}</span>
                      </div>
                      <span>{new Date(forensicCase.created).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Case Details */}
          <div>
            {selectedCaseData ? (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Case Details</h3>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(selectedCaseData.status)}`}>
                      {selectedCaseData.status.replace('_', ' ').toUpperCase()}
                    </span>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getPriorityColor(selectedCaseData.priority)}`}>
                      {selectedCaseData.priority.toUpperCase()}
                    </span>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Lead Investigator</label>
                    <div className="flex items-center space-x-2">
                      <User className="h-4 w-4 text-gray-400" />
                      <span className="text-sm text-gray-900">{selectedCaseData.investigator}</span>
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Evidence Collection</label>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Evidence Items:</span>
                        <span className="font-medium">{selectedCaseData.evidence_count}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span>Artifacts Found:</span>
                        <span className="font-medium">{selectedCaseData.artifacts_count}</span>
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Timeline</label>
                    <div className="text-sm text-gray-600 space-y-1">
                      <div>Created: {new Date(selectedCaseData.created).toLocaleString()}</div>
                      <div>Updated: {new Date(selectedCaseData.updated).toLocaleString()}</div>
                    </div>
                  </div>
                </div>
                
                <div className="mt-6 pt-4 border-t border-gray-200 space-y-2">
                   <button 
                     onClick={() => setActiveTab('evidence')}
                     className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                   >
                     <Eye className="h-4 w-4" />
                     <span>View Evidence</span>
                   </button>
                   <button 
                     onClick={() => handleGenerateReport(selectedCaseData.id)}
                     className="w-full flex items-center justify-center space-x-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors"
                   >
                     <Download className="h-4 w-4" />
                     <span>Generate Report</span>
                   </button>
                   <button 
                     onClick={() => handleStartAnalysis(selectedCaseData.id)}
                     className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
                   >
                     <Play className="h-4 w-4" />
                     <span>Start Analysis</span>
                   </button>
                 </div>
              </div>
            ) : (
              <div className="bg-white rounded-lg shadow-sm p-6 text-center text-gray-500">
                <FileText className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>Select a case to view details</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Evidence Tab */}
      {activeTab === 'evidence' && (
        <div className="space-y-6">
          {selectedCaseData && (
            <div className="bg-white rounded-lg shadow-sm">
               <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
                 <h3 className="text-lg font-semibold text-gray-900">Evidence Collection - {selectedCaseData.name}</h3>
                 <button 
                   onClick={() => setShowNewEvidence(true)}
                   className="flex items-center space-x-2 px-3 py-1 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                 >
                   <Plus className="h-4 w-4" />
                   <span>Add Evidence</span>
                 </button>
               </div>
              <div className="divide-y divide-gray-200">
                {caseEvidence.map((evidenceItem) => (
                  <div key={evidenceItem.id} className="p-6">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start space-x-3">
                        {getEvidenceIcon(evidenceItem.type)}
                        <div>
                          <h4 className="font-medium text-gray-900">{evidenceItem.name}</h4>
                          <p className="text-sm text-gray-600 capitalize">{evidenceItem.type.replace('_', ' ')}</p>
                        </div>
                      </div>
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        evidenceItem.status === 'analyzed' ? 'text-green-700 bg-green-100' :
                        evidenceItem.status === 'processing' ? 'text-blue-700 bg-blue-100' :
                        'text-red-700 bg-red-100'
                      }`}>
                        {evidenceItem.status.toUpperCase()}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-gray-600">
                      <div>
                        <span className="font-medium">Size:</span> {evidenceItem.size}
                      </div>
                      <div>
                        <span className="font-medium">Source:</span> {evidenceItem.source}
                      </div>
                      <div>
                        <span className="font-medium">Collected:</span> {new Date(evidenceItem.collected).toLocaleString()}
                      </div>
                    </div>
                    
                    <div className="mt-3">
                      <div className="flex items-center space-x-2 text-sm text-gray-600">
                        <Hash className="h-4 w-4" />
                        <span className="font-mono">{evidenceItem.hash}</span>
                      </div>
                    </div>
                    
                    <div className="mt-4 flex space-x-2">
                       <button 
                         onClick={() => handleStartAnalysis(selectedCase!)}
                         className="flex items-center space-x-1 px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors"
                       >
                         <Eye className="h-3 w-3" />
                         <span>Analyze</span>
                       </button>
                       <button 
                         onClick={() => handleExportEvidence(evidenceItem.id)}
                         className="flex items-center space-x-1 px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors"
                       >
                         <Download className="h-3 w-3" />
                         <span>Export</span>
                       </button>
                     </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {!selectedCaseData && (
            <div className="bg-white rounded-lg shadow-sm p-6 text-center text-gray-500">
              <HardDrive className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>Select a case to view evidence</p>
            </div>
          )}
        </div>
      )}

      {/* Analysis Tab */}
      {activeTab === 'analysis' && (
        <div className="space-y-6">
          {selectedCaseData && (
            <div className="bg-white rounded-lg shadow-sm">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Forensic Artifacts - {selectedCaseData.name}</h3>
              </div>
              <div className="divide-y divide-gray-200">
                {caseArtifacts.map((artifact) => (
                  <div key={artifact.id} className="p-6">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="font-medium text-gray-900">{artifact.type}</h4>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            artifact.relevance === 'high' ? 'text-red-700 bg-red-100' :
                            artifact.relevance === 'medium' ? 'text-yellow-700 bg-yellow-100' :
                            'text-green-700 bg-green-100'
                          }`}>
                            {artifact.relevance.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600">{artifact.description}</p>
                      </div>
                      <div className="text-sm text-gray-500">
                        {new Date(artifact.timestamp).toLocaleString()}
                      </div>
                    </div>
                    
                    <div className="flex flex-wrap gap-1 mt-3">
                      {artifact.tags.map((tag, index) => (
                        <span key={index} className="inline-flex px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {!selectedCaseData && (
            <div className="bg-white rounded-lg shadow-sm p-6 text-center text-gray-500">
              <Search className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>Select a case to view analysis results</p>
            </div>
          )}
        </div>
      )}

      {/* Timeline Tab */}
      {activeTab === 'timeline' && (
        <div className="bg-white rounded-lg shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Investigation Timeline</h3>
          </div>
          {selectedCaseData ? (
            <div className="p-6">
              <div className="space-y-6">
                {timelineEvents.map((event) => (
                  <div key={event.id} className="flex items-start space-x-4">
                    <div className="flex-shrink-0 w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-gray-900">{event.event_type}</span>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getConfidenceColor(event.confidence)}`}>
                            {event.confidence.toUpperCase()}
                          </span>
                        </div>
                        <span className="text-sm text-gray-500">{new Date(event.timestamp).toLocaleString()}</span>
                      </div>
                      <p className="text-sm text-gray-600 mb-1">{event.description}</p>
                      <p className="text-xs text-gray-500">Source: {event.source}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-gray-500">
              <Clock className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>Select a case to view timeline</p>
            </div>
          )}
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {cases.map((forensicCase) => (
              <div key={forensicCase.id} className="bg-white rounded-lg shadow-sm p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900">Investigation Report</h3>
                  <FileText className="h-6 w-6 text-blue-600" />
                </div>
                <p className="text-gray-600 mb-4">{forensicCase.name}</p>
                
                <div className="space-y-2 mb-4">
                  <div className="flex justify-between text-sm">
                    <span>Status:</span>
                    <span className="font-medium capitalize">{forensicCase.status.replace('_', ' ')}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Evidence Items:</span>
                    <span className="font-medium">{forensicCase.evidence_count}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Artifacts:</span>
                    <span className="font-medium">{forensicCase.artifacts_count}</span>
                  </div>
                </div>
                
                <button 
                   onClick={() => handleGenerateReport(forensicCase.id)}
                   className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                 >
                   <Download className="h-4 w-4" />
                   <span>Download Report</span>
                 </button>
              </div>
            ))}
          </div>
        </div>
      )}
      </div>

      {/* New Case Modal */}
      {showNewCase && (
       <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
         <div className="bg-white rounded-lg p-6 w-full max-w-md">
           <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Investigation</h3>
           <form onSubmit={handleCreateCase}>
             <div className="space-y-4">
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Case Name</label>
                 <input
                   type="text"
                   value={newCaseForm.name}
                   onChange={(e) => setNewCaseForm(prev => ({ ...prev, name: e.target.value }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                   required
                 />
               </div>
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                 <textarea
                   value={newCaseForm.description}
                   onChange={(e) => setNewCaseForm(prev => ({ ...prev, description: e.target.value }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                   rows={3}
                   required
                 />
               </div>
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Priority</label>
                 <select
                   value={newCaseForm.priority}
                   onChange={(e) => setNewCaseForm(prev => ({ ...prev, priority: e.target.value as any }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                 >
                   <option value="low">Low</option>
                   <option value="medium">Medium</option>
                   <option value="high">High</option>
                   <option value="critical">Critical</option>
                 </select>
               </div>
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Lead Investigator</label>
                 <input
                   type="text"
                   value={newCaseForm.investigator}
                   onChange={(e) => setNewCaseForm(prev => ({ ...prev, investigator: e.target.value }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                   required
                 />
               </div>
             </div>
             <div className="flex space-x-3 mt-6">
               <button
                 type="submit"
                 className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
               >
                 Create Case
               </button>
               <button
                 type="button"
                 onClick={() => setShowNewCase(false)}
                 className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50 transition-colors"
               >
                 Cancel
               </button>
             </div>
           </form>
         </div>
       </div>
     )}

     {/* New Evidence Modal */}
     {showNewEvidence && selectedCase && (
       <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
         <div className="bg-white rounded-lg p-6 w-full max-w-md">
           <h3 className="text-lg font-semibold text-gray-900 mb-4">Add Evidence</h3>
           <form onSubmit={handleCreateEvidence}>
             <div className="space-y-4">
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Evidence Name</label>
                 <input
                   type="text"
                   value={newEvidenceForm.name}
                   onChange={(e) => setNewEvidenceForm(prev => ({ ...prev, name: e.target.value }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                   required
                 />
               </div>
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Evidence Type</label>
                 <select
                   value={newEvidenceForm.type}
                   onChange={(e) => setNewEvidenceForm(prev => ({ ...prev, type: e.target.value as any }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                 >
                   <option value="disk_image">Disk Image</option>
                   <option value="memory_dump">Memory Dump</option>
                   <option value="network_capture">Network Capture</option>
                   <option value="log_file">Log File</option>
                   <option value="registry">Registry</option>
                   <option value="file_system">File System</option>
                 </select>
               </div>
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Source</label>
                 <input
                   type="text"
                   value={newEvidenceForm.source}
                   onChange={(e) => setNewEvidenceForm(prev => ({ ...prev, source: e.target.value }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                   required
                 />
               </div>
               <div>
                 <label className="block text-sm font-medium text-gray-700 mb-1">Hash (SHA256)</label>
                 <input
                   type="text"
                   value={newEvidenceForm.hash}
                   onChange={(e) => setNewEvidenceForm(prev => ({ ...prev, hash: e.target.value }))}
                   className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                   placeholder="sha256:..."
                   required
                 />
               </div>
             </div>
             <div className="flex space-x-3 mt-6">
               <button
                 type="submit"
                 className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
               >
                 Add Evidence
               </button>
               <button
                 type="button"
                 onClick={() => setShowNewEvidence(false)}
                 className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50 transition-colors"
               >
                 Cancel
               </button>
             </div>
           </form>
         </div>
       </div>
     )}
    </>
  )
}

export default ForensicsLab