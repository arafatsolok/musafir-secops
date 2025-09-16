import React, { useState, useEffect } from 'react'
import { Play, Download, Save, History, AlertTriangle, CheckCircle } from 'lucide-react'

interface QueryResult {
  columns: string[]
  rows: any[]
  executionTime: number
  rowCount: number
}

interface SavedQuery {
  id: string
  name: string
  query: string
  description: string
  created_at: string
  tags: string[]
}

const QueryWorkbench: React.FC = () => {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<QueryResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([])
  const [queryHistory, setQueryHistory] = useState<string[]>([])
  const [selectedQuery, setSelectedQuery] = useState<string | null>(null)

  // Sample queries
  const sampleQueries = [
    {
      name: "Recent High Severity Alerts",
      query: `SELECT 
  timestamp,
  title,
  severity,
  asset_id,
  user_id
FROM musafir_correlated_alerts 
WHERE severity IN ('high', 'critical')
  AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY timestamp DESC
LIMIT 100`
    },
    {
      name: "Ransomware Activity",
      query: `SELECT 
  timestamp,
  asset_id,
  user_id,
  title,
  attack_chain,
  score
FROM musafir_correlated_alerts 
WHERE title LIKE '%ransomware%'
  AND timestamp >= now() - INTERVAL 7 DAY
ORDER BY score DESC`
    },
    {
      name: "UEBA Anomalies",
      query: `SELECT 
  timestamp,
  user_id,
  asset_id,
  reason,
  score,
  anomalies
FROM musafir_ueba_alerts 
WHERE score > 0.7
  AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY score DESC`
    },
    {
      name: "Threat Intel Matches",
      query: `SELECT 
  timestamp,
  indicator,
  indicator_type,
  source,
  confidence,
  asset_id
FROM musafir_ti_alerts 
WHERE confidence > 0.8
  AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY confidence DESC`
    },
    {
      name: "Sandbox Results",
      query: `SELECT 
  timestamp,
  verdict,
  score,
  environment,
  iocs,
  behavior
FROM musafir_sandbox_results 
WHERE verdict != 'clean'
  AND timestamp >= now() - INTERVAL 7 DAY
ORDER BY score DESC`
    }
  ]

  useEffect(() => {
    loadSavedQueries()
    loadQueryHistory()
  }, [])

  const loadSavedQueries = async () => {
    try {
      const response = await fetch('/api/queries/saved')
      if (response.ok) {
        const queries = await response.json()
        setSavedQueries(queries)
      }
    } catch (err) {
      console.error('Failed to load saved queries:', err)
    }
  }

  const loadQueryHistory = async () => {
    try {
      const response = await fetch('/api/queries/history')
      if (response.ok) {
        const history = await response.json()
        setQueryHistory(history)
      }
    } catch (err) {
      console.error('Failed to load query history:', err)
    }
  }

  const executeQuery = async () => {
    if (!query.trim()) return

    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await fetch('/api/query/execute', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: query.trim() }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Query execution failed')
      }

      const data = await response.json()
      setResults(data)
      
      // Add to history
      if (!queryHistory.includes(query)) {
        setQueryHistory(prev => [query, ...prev.slice(0, 49)]) // Keep last 50
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  const saveQuery = async () => {
    if (!query.trim()) return

    const name = prompt('Enter query name:')
    if (!name) return

    try {
      const response = await fetch('/api/queries/save', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name,
          query: query.trim(),
          description: '',
          tags: []
        }),
      })

      if (response.ok) {
        loadSavedQueries()
        alert('Query saved successfully!')
      }
    } catch (err) {
      console.error('Failed to save query:', err)
    }
  }

  const loadQuery = (queryText: string) => {
    setQuery(queryText)
    setSelectedQuery(queryText)
  }

  const exportResults = () => {
    if (!results) return

    const csv = [
      results.columns.join(','),
      ...results.rows.map(row => 
        results.columns.map(col => `"${row[col] || ''}"`).join(',')
      )
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `query-results-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="h-full flex flex-col bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b px-6 py-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-semibold text-gray-900">Query Workbench</h1>
          <div className="flex items-center space-x-2">
            <button
              onClick={executeQuery}
              disabled={loading || !query.trim()}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
            >
              <Play className="h-4 w-4 mr-2" />
              {loading ? 'Executing...' : 'Execute'}
            </button>
            <button
              onClick={saveQuery}
              disabled={!query.trim()}
              className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
            >
              <Save className="h-4 w-4 mr-2" />
              Save
            </button>
            {results && (
              <button
                onClick={exportResults}
                className="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
              >
                <Download className="h-4 w-4 mr-2" />
                Export
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 flex">
        {/* Sidebar */}
        <div className="w-80 bg-white border-r flex flex-col">
          {/* Sample Queries */}
          <div className="p-4 border-b">
            <h3 className="text-sm font-medium text-gray-900 mb-3">Sample Queries</h3>
            <div className="space-y-2">
              {sampleQueries.map((sample, index) => (
                <button
                  key={index}
                  onClick={() => loadQuery(sample.query)}
                  className="w-full text-left p-2 text-sm text-gray-700 hover:bg-gray-100 rounded"
                >
                  {sample.name}
                </button>
              ))}
            </div>
          </div>

          {/* Saved Queries */}
          <div className="p-4 border-b">
            <h3 className="text-sm font-medium text-gray-900 mb-3">Saved Queries</h3>
            <div className="space-y-2">
              {savedQueries.map((saved) => (
                <button
                  key={saved.id}
                  onClick={() => loadQuery(saved.query)}
                  className="w-full text-left p-2 text-sm text-gray-700 hover:bg-gray-100 rounded"
                >
                  {saved.name}
                </button>
              ))}
            </div>
          </div>

          {/* Query History */}
          <div className="p-4 flex-1">
            <h3 className="text-sm font-medium text-gray-900 mb-3">Query History</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {queryHistory.map((historyQuery, index) => (
                <button
                  key={index}
                  onClick={() => loadQuery(historyQuery)}
                  className="w-full text-left p-2 text-xs text-gray-600 hover:bg-gray-100 rounded truncate"
                >
                  {historyQuery.substring(0, 50)}...
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col">
          {/* Query Editor */}
          <div className="flex-1 p-6">
            <div className="h-full flex flex-col">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                KQL/SQL Query
              </label>
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Enter your KQL or SQL query here..."
                className="flex-1 w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
                style={{ resize: 'none' }}
              />
            </div>
          </div>

          {/* Results */}
          {error && (
            <div className="mx-6 mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
              <div className="flex">
                <AlertTriangle className="h-5 w-5 text-red-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Query Error</h3>
                  <p className="mt-1 text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          )}

          {results && (
            <div className="mx-6 mb-6">
              <div className="bg-white border border-gray-200 rounded-md">
                <div className="px-4 py-3 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium text-gray-900">Query Results</h3>
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                      <span>{results.rowCount} rows</span>
                      <span>{results.executionTime}ms</span>
                    </div>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        {results.columns.map((column) => (
                          <th
                            key={column}
                            className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                          >
                            {column}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {results.rows.map((row, index) => (
                        <tr key={index}>
                          {results.columns.map((column) => (
                            <td
                              key={column}
                              className="px-6 py-4 whitespace-nowrap text-sm text-gray-900"
                            >
                              {row[column] || '-'}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default QueryWorkbench
