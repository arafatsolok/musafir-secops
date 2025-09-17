const express = require('express')
const { createProxyMiddleware } = require('http-proxy-middleware')
const cors = require('cors')

const app = express()
const PORT = 3001

// Enable CORS for all routes
app.use(cors())

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// Service status checker
app.get('/api/service-status/:service', async (req, res) => {
  const { service } = req.params
  const serviceUrls = {
    'main-dashboard': 'http://localhost:3000',
    'grafana': 'http://localhost:3001',
    'prometheus': 'http://localhost:9090',
    'jaeger': 'http://localhost:16686',
    'neo4j': 'http://localhost:7474',
    'rabbitmq': 'http://localhost:15672',
    'minio': 'http://localhost:9002'
  }

  const url = serviceUrls[service]
  if (!url) {
    return res.status(404).json({ error: 'Service not found' })
  }

  try {
    const response = await fetch(url, { 
      method: 'HEAD',
      timeout: 5000
    })
    res.json({ 
      service, 
      status: 'healthy', 
      url,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    res.json({ 
      service, 
      status: 'unhealthy', 
      url,
      error: error.message,
      timestamp: new Date().toISOString()
    })
  }
})

// Gateway API proxy
const gatewayUrl = process.env.GATEWAY_URL || 'http://localhost:8000'
app.use('/api', createProxyMiddleware({
  target: gatewayUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api': '/api/v1' // Rewrite path to match gateway API version
  },
  onProxyReq: (proxyReq, req, res) => {
    // Add auth token if available
    if (req.headers.authorization) {
      proxyReq.setHeader('Authorization', req.headers.authorization)
    }
    
    // Log request for debugging
    console.log(`[Proxy] ${req.method} ${req.path} -> ${gatewayUrl}/api/v1${req.path.replace(/^\/api/, '')}`)
  },
  onError: (err, req, res) => {
    console.error(`[Proxy Error] ${err.message}`)
    res.status(500).json({ 
      error: 'Gateway service unavailable',
      message: 'Unable to connect to backend services',
      timestamp: new Date().toISOString()
    })
  }
}))

// WebSocket proxy for real-time updates
const wsProxy = createProxyMiddleware('/ws', {
  target: gatewayUrl,
  ws: true,
  changeOrigin: true,
  onError: (err, req, res) => {
    console.error(`[WebSocket Error] ${err.message}`)
  }
})
app.use(wsProxy)

// Start the server
app.listen(PORT, () => {
  console.log(`Proxy server running on http://localhost:${PORT}`)
  console.log(`Proxying API requests to ${gatewayUrl}`)
})
