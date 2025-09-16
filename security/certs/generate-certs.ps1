# Generate self-signed certificates for mTLS (development only)
# In production, use proper CA and certificate management

Write-Host "Generating mTLS certificates for development..." -ForegroundColor Green

# Create certs directory
if (-not (Test-Path "certs")) {
    New-Item -ItemType Directory -Path "certs"
}

# Generate CA private key
openssl genrsa -out certs/ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key certs/ca-key.pem -out certs/ca-cert.pem -subj "/C=US/ST=CA/L=SF/O=MUSAFIR/OU=Dev/CN=MUSAFIR-CA"

# Generate server private key
openssl genrsa -out certs/server-key.pem 4096

# Generate server certificate request
openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/C=US/ST=CA/L=SF/O=MUSAFIR/OU=Dev/CN=localhost"

# Generate server certificate signed by CA
openssl x509 -req -days 365 -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -out certs/server-cert.pem -CAcreateserial

# Generate client private key
openssl genrsa -out certs/client-key.pem 4096

# Generate client certificate request
openssl req -new -key certs/client-key.pem -out certs/client.csr -subj "/C=US/ST=CA/L=SF/O=MUSAFIR/OU=Dev/CN=musafir-agent"

# Generate client certificate signed by CA
openssl x509 -req -days 365 -in certs/client.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -out certs/client-cert.pem -CAcreateserial

# Clean up CSR files
Remove-Item certs/server.csr, certs/client.csr

Write-Host "Certificates generated successfully!" -ForegroundColor Green
Write-Host "CA Certificate: certs/ca-cert.pem" -ForegroundColor Yellow
Write-Host "Server Certificate: certs/server-cert.pem" -ForegroundColor Yellow
Write-Host "Server Key: certs/server-key.pem" -ForegroundColor Yellow
Write-Host "Client Certificate: certs/client-cert.pem" -ForegroundColor Yellow
Write-Host "Client Key: certs/client-key.pem" -ForegroundColor Yellow
