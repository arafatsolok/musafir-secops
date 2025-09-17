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

// Proxy for all services
app.use('/api/grafana', createProxyMiddleware({
  target: 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: { '^/api/grafana': '' }
}))

app.use('/api/prometheus', createProxyMiddleware({
  target: 'http://localhost:9090',
  changeOrigin: true,
  pathRewrite: { '^/api/prometheus': '' }
}))

app.use('/api/jaeger', createProxyMiddleware({
  target: 'http://localhost:16686',
  changeOrigin: true,
  pathRewrite: { '^/api/jaeger': '' }
}))

app.use('/api/neo4j', createProxyMiddleware({
  target: 'http://localhost:7474',
  changeOrigin: true,
  pathRewrite: { '^/api/neo4j': '' }
}))

app.use('/api/rabbitmq', createProxyMiddleware({
  target: 'http://localhost:15672',
  changeOrigin: true,
  pathRewrite: { '^/api/rabbitmq': '' }
}))

app.use('/api/minio', createProxyMiddleware({
  target: 'http://localhost:9002',
  changeOrigin: true,
  pathRewrite: { '^/api/minio': '' }
}))

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`)
  console.log(`Health check: http://localhost:${PORT}/health`)
  console.log(`Service status: http://localhost:${PORT}/api/service-status/{service}`)
})
