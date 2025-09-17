import React, { useState } from 'react'

const AgentEnrollment: React.FC = () => {
  const [token, setToken] = useState<string>('')
  const [serverUrl, setServerUrl] = useState<string>(
    (import.meta as any).env?.VITE_API_BASE || window.location.origin
  )
  const [agentLink, setAgentLink] = useState<string>('')
  const [error, setError] = useState<string>('')

  const generateToken = async () => {
    setError('')
    try {
      const jwt = localStorage.getItem('musafir_jwt') || ''
      const res = await fetch('/api/admin/agents', {
        method: 'POST',
        headers: jwt ? { Authorization: `Bearer ${jwt}` } : {},
      })
      if (!res.ok) throw new Error('Failed to create token')
      const data = await res.json()
      setToken(data.enrollment_token)
      const gw = serverUrl.replace(/\/$/, '')
      setAgentLink(`${gw}/v1/enroll`)
    } catch (e: any) {
      setError(e.message || 'Unknown error')
    }
  }

  const qrSrc = token
    ? `https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(
        JSON.stringify({ token, server: serverUrl })
      )}`
    : ''

  return (
    <div className="bg-white rounded-lg shadow border p-6">
      <h2 className="text-xl font-semibold mb-4">Agent Enrollment</h2>

      <div className="flex items-end gap-3 mb-4">
        <div className="flex-1">
          <label className="block text-sm text-gray-600 mb-1">Gateway URL</label>
          <input
            className="w-full border rounded px-3 py-2"
            value={serverUrl}
            onChange={(e) => setServerUrl(e.target.value)}
            placeholder="http://your-gateway:8080"
          />
        </div>
        <button
          onClick={generateToken}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Generate Token
        </button>
      </div>

      {error && <div className="text-red-600 text-sm mb-3">{error}</div>}

      {token && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <div className="mb-2 text-sm text-gray-600">Enrollment Token</div>
            <div className="font-mono break-all p-3 border rounded bg-gray-50">{token}</div>
            <div className="mt-4 text-sm text-gray-600">Agent Enroll Endpoint</div>
            <div className="font-mono break-all p-3 border rounded bg-gray-50">{agentLink}</div>
          </div>
          <div className="flex flex-col items-center">
            <div className="text-sm text-gray-600 mb-2">Scan on target PC</div>
            <img src={qrSrc} alt="QR" className="border rounded" />
          </div>
        </div>
      )}

      <div className="mt-6">
        <h3 className="font-semibold mb-2">Windows Install Instructions</h3>
        <ol className="list-decimal ml-5 text-sm text-gray-700 space-y-1">
          <li>Download agent.exe from your distribution location.</li>
          <li>Run agent, paste the Enrollment Token above and Gateway URL.</li>
          <li>Agent enrolls and retrieves per-agent HMAC; no server secrets needed.</li>
        </ol>
      </div>

      <div className="mt-6">
        <h3 className="font-semibold mb-2">Enrolled Agents (recent)</h3>
        <div className="text-sm text-gray-600">Coming soon: live list from gateway.</div>
      </div>
    </div>
  )
}

export default AgentEnrollment
