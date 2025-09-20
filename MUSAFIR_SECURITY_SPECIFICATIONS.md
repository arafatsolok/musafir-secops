# MUSAFIR Security Specifications

## Overview
This document outlines the comprehensive security architecture for the MUSAFIR central web UI platform, covering authentication, authorization, encryption, secure communications, and security best practices for EDR, XDR, and SIEM operations.

## 1. Security Architecture Overview

```
[Agent] ←→ [mTLS] ←→ [API Gateway] ←→ [Auth Service] ←→ [Backend Services]
                           ↓
                    [JWT Validation]
                           ↓
                    [RBAC Authorization]
                           ↓
                    [Audit Logging]
```

## 2. Authentication System

### 2.1 Multi-Factor Authentication (MFA)

```go
// internal/auth/mfa.go
package auth

import (
    "crypto/rand"
    "encoding/base32"
    "fmt"
    "time"
    
    "github.com/pquerna/otp/totp"
)

type MFAService struct {
    issuer string
}

func NewMFAService(issuer string) *MFAService {
    return &MFAService{issuer: issuer}
}

func (m *MFAService) GenerateSecret(username string) (*MFASecret, error) {
    secret := make([]byte, 20)
    _, err := rand.Read(secret)
    if err != nil {
        return nil, err
    }
    
    secretBase32 := base32.StdEncoding.EncodeToString(secret)
    
    qrCode, err := m.generateQRCode(username, secretBase32)
    if err != nil {
        return nil, err
    }
    
    return &MFASecret{
        Secret:   secretBase32,
        QRCode:   qrCode,
        Username: username,
    }, nil
}

func (m *MFAService) ValidateToken(secret, token string) bool {
    return totp.Validate(token, secret)
}

type MFASecret struct {
    Secret   string `json:"secret"`
    QRCode   string `json:"qr_code"`
    Username string `json:"username"`
}
```

### 2.2 JWT Token Management

```go
// internal/auth/jwt.go
package auth

import (
    "crypto/rsa"
    "time"
    
    "github.com/golang-jwt/jwt/v4"
)

type JWTService struct {
    privateKey *rsa.PrivateKey
    publicKey  *rsa.PublicKey
    issuer     string
}

type Claims struct {
    UserID      string   `json:"user_id"`
    Username    string   `json:"username"`
    Email       string   `json:"email"`
    Roles       []string `json:"roles"`
    Permissions []string `json:"permissions"`
    SessionID   string   `json:"session_id"`
    jwt.RegisteredClaims
}

func NewJWTService(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer string) *JWTService {
    return &JWTService{
        privateKey: privateKey,
        publicKey:  publicKey,
        issuer:     issuer,
    }
}

func (j *JWTService) GenerateToken(user *User, sessionID string) (string, error) {
    claims := &Claims{
        UserID:      user.ID,
        Username:    user.Username,
        Email:       user.Email,
        Roles:       user.Roles,
        Permissions: user.GetPermissions(),
        SessionID:   sessionID,
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    j.issuer,
            Subject:   user.ID,
            Audience:  []string{"musafir-web-ui"},
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
            NotBefore: jwt.NewNumericDate(time.Now()),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    return token.SignedString(j.privateKey)
}

func (j *JWTService) ValidateToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return j.publicKey, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, jwt.ErrInvalidKey
}
```

### 2.3 Session Management

```go
// internal/auth/session.go
package auth

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "time"
    
    "github.com/go-redis/redis/v8"
)

type SessionManager struct {
    redis  *redis.Client
    expiry time.Duration
}

type Session struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id"`
    CreatedAt time.Time `json:"created_at"`
    LastSeen  time.Time `json:"last_seen"`
    IPAddress string    `json:"ip_address"`
    UserAgent string    `json:"user_agent"`
    Active    bool      `json:"active"`
}

func NewSessionManager(redisClient *redis.Client) *SessionManager {
    return &SessionManager{
        redis:  redisClient,
        expiry: 24 * time.Hour,
    }
}

func (sm *SessionManager) CreateSession(ctx context.Context, userID, ipAddress, userAgent string) (*Session, error) {
    sessionID, err := sm.generateSessionID()
    if err != nil {
        return nil, err
    }
    
    session := &Session{
        ID:        sessionID,
        UserID:    userID,
        CreatedAt: time.Now(),
        LastSeen:  time.Now(),
        IPAddress: ipAddress,
        UserAgent: userAgent,
        Active:    true,
    }
    
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    sessionData, _ := json.Marshal(session)
    
    err = sm.redis.Set(ctx, sessionKey, sessionData, sm.expiry).Err()
    if err != nil {
        return nil, err
    }
    
    return session, nil
}

func (sm *SessionManager) ValidateSession(ctx context.Context, sessionID string) (*Session, error) {
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    sessionData, err := sm.redis.Get(ctx, sessionKey).Result()
    if err != nil {
        return nil, err
    }
    
    var session Session
    if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
        return nil, err
    }
    
    if !session.Active {
        return nil, fmt.Errorf("session is inactive")
    }
    
    // Update last seen
    session.LastSeen = time.Now()
    updatedData, _ := json.Marshal(session)
    sm.redis.Set(ctx, sessionKey, updatedData, sm.expiry)
    
    return &session, nil
}

func (sm *SessionManager) generateSessionID() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}
```

## 3. Authorization System (RBAC)

### 3.1 Role-Based Access Control

```go
// internal/auth/rbac.go
package auth

import (
    "context"
    "fmt"
)

type Permission string

const (
    // Dashboard permissions
    ViewDashboard     Permission = "dashboard:view"
    ManageDashboard   Permission = "dashboard:manage"
    
    // Alert permissions
    ViewAlerts        Permission = "alerts:view"
    ManageAlerts      Permission = "alerts:manage"
    AcknowledgeAlerts Permission = "alerts:acknowledge"
    
    // Investigation permissions
    ViewInvestigations   Permission = "investigations:view"
    CreateInvestigations Permission = "investigations:create"
    ManageInvestigations Permission = "investigations:manage"
    
    // Agent permissions
    ViewAgents    Permission = "agents:view"
    ManageAgents  Permission = "agents:manage"
    DeployAgents  Permission = "agents:deploy"
    
    // User management permissions
    ViewUsers    Permission = "users:view"
    ManageUsers  Permission = "users:manage"
    CreateUsers  Permission = "users:create"
    DeleteUsers  Permission = "users:delete"
    
    // System permissions
    ViewSystemConfig    Permission = "system:view_config"
    ManageSystemConfig  Permission = "system:manage_config"
    ViewAuditLogs      Permission = "system:view_audit"
    ManageIntegrations Permission = "system:manage_integrations"
)

type Role struct {
    ID          string       `json:"id"`
    Name        string       `json:"name"`
    Description string       `json:"description"`
    Permissions []Permission `json:"permissions"`
    CreatedAt   time.Time    `json:"created_at"`
    UpdatedAt   time.Time    `json:"updated_at"`
}

var DefaultRoles = map[string]Role{
    "admin": {
        ID:          "admin",
        Name:        "Administrator",
        Description: "Full system access",
        Permissions: []Permission{
            ViewDashboard, ManageDashboard,
            ViewAlerts, ManageAlerts, AcknowledgeAlerts,
            ViewInvestigations, CreateInvestigations, ManageInvestigations,
            ViewAgents, ManageAgents, DeployAgents,
            ViewUsers, ManageUsers, CreateUsers, DeleteUsers,
            ViewSystemConfig, ManageSystemConfig, ViewAuditLogs, ManageIntegrations,
        },
    },
    "analyst": {
        ID:          "analyst",
        Name:        "Security Analyst",
        Description: "Security analysis and investigation",
        Permissions: []Permission{
            ViewDashboard,
            ViewAlerts, AcknowledgeAlerts,
            ViewInvestigations, CreateInvestigations,
            ViewAgents,
        },
    },
    "operator": {
        ID:          "operator",
        Name:        "SOC Operator",
        Description: "Security operations monitoring",
        Permissions: []Permission{
            ViewDashboard,
            ViewAlerts, AcknowledgeAlerts,
            ViewInvestigations,
            ViewAgents,
        },
    },
    "viewer": {
        ID:          "viewer",
        Name:        "Read-Only Viewer",
        Description: "View-only access to dashboards and alerts",
        Permissions: []Permission{
            ViewDashboard,
            ViewAlerts,
            ViewInvestigations,
            ViewAgents,
        },
    },
}

type RBACService struct {
    roles map[string]Role
}

func NewRBACService() *RBACService {
    return &RBACService{
        roles: DefaultRoles,
    }
}

func (r *RBACService) HasPermission(userRoles []string, permission Permission) bool {
    for _, roleName := range userRoles {
        if role, exists := r.roles[roleName]; exists {
            for _, perm := range role.Permissions {
                if perm == permission {
                    return true
                }
            }
        }
    }
    return false
}

func (r *RBACService) GetUserPermissions(userRoles []string) []Permission {
    permissionSet := make(map[Permission]bool)
    
    for _, roleName := range userRoles {
        if role, exists := r.roles[roleName]; exists {
            for _, perm := range role.Permissions {
                permissionSet[perm] = true
            }
        }
    }
    
    var permissions []Permission
    for perm := range permissionSet {
        permissions = append(permissions, perm)
    }
    
    return permissions
}
```

### 3.2 Authorization Middleware

```go
// internal/middleware/auth.go
package middleware

import (
    "context"
    "net/http"
    "strings"
    
    "github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
    jwtService  *auth.JWTService
    rbacService *auth.RBACService
}

func NewAuthMiddleware(jwtService *auth.JWTService, rbacService *auth.RBACService) *AuthMiddleware {
    return &AuthMiddleware{
        jwtService:  jwtService,
        rbacService: rbacService,
    }
}

func (am *AuthMiddleware) RequireAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := am.jwtService.ValidateToken(tokenString)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
        
        c.Set("user_id", claims.UserID)
        c.Set("username", claims.Username)
        c.Set("roles", claims.Roles)
        c.Set("permissions", claims.Permissions)
        c.Next()
    }
}

func (am *AuthMiddleware) RequirePermission(permission auth.Permission) gin.HandlerFunc {
    return func(c *gin.Context) {
        roles, exists := c.Get("roles")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{"error": "No roles found"})
            c.Abort()
            return
        }
        
        userRoles := roles.([]string)
        if !am.rbacService.HasPermission(userRoles, permission) {
            c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

## 4. Encryption and Data Protection

### 4.1 Data Encryption at Rest

```go
// internal/encryption/aes.go
package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
)

type AESEncryption struct {
    key []byte
}

func NewAESEncryption(key []byte) *AESEncryption {
    return &AESEncryption{key: key}
}

func (ae *AESEncryption) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(ae.key)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (ae *AESEncryption) Decrypt(ciphertext string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    
    block, err := aes.NewCipher(ae.key)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", fmt.Errorf("ciphertext too short")
    }
    
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    
    return string(plaintext), nil
}
```

### 4.2 TLS Configuration

```go
// internal/tls/config.go
package tls

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
)

type TLSConfig struct {
    CertFile   string
    KeyFile    string
    CAFile     string
    ServerName string
}

func (tc *TLSConfig) GetServerTLSConfig() (*tls.Config, error) {
    cert, err := tls.LoadX509KeyPair(tc.CertFile, tc.KeyFile)
    if err != nil {
        return nil, fmt.Errorf("failed to load key pair: %v", err)
    }
    
    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        },
    }
    
    if tc.CAFile != "" {
        caCert, err := ioutil.ReadFile(tc.CAFile)
        if err != nil {
            return nil, fmt.Errorf("failed to read CA file: %v", err)
        }
        
        caCertPool := x509.NewCertPool()
        caCertPool.AppendCertsFromPEM(caCert)
        config.ClientCAs = caCertPool
        config.ClientAuth = tls.RequireAndVerifyClientCert
    }
    
    return config, nil
}

func (tc *TLSConfig) GetClientTLSConfig() (*tls.Config, error) {
    config := &tls.Config{
        ServerName: tc.ServerName,
        MinVersion: tls.VersionTLS12,
    }
    
    if tc.CertFile != "" && tc.KeyFile != "" {
        cert, err := tls.LoadX509KeyPair(tc.CertFile, tc.KeyFile)
        if err != nil {
            return nil, fmt.Errorf("failed to load client certificate: %v", err)
        }
        config.Certificates = []tls.Certificate{cert}
    }
    
    if tc.CAFile != "" {
        caCert, err := ioutil.ReadFile(tc.CAFile)
        if err != nil {
            return nil, fmt.Errorf("failed to read CA file: %v", err)
        }
        
        caCertPool := x509.NewCertPool()
        caCertPool.AppendCertsFromPEM(caCert)
        config.RootCAs = caCertPool
    }
    
    return config, nil
}
```

## 5. Agent Authentication and Communication Security

### 5.1 Mutual TLS (mTLS) for Agent Communication

```go
// internal/agent/auth.go
package agent

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net/http"
)

type AgentAuthService struct {
    caCertPool *x509.CertPool
    agentDB    AgentDatabase
}

func NewAgentAuthService(caCertPath string, agentDB AgentDatabase) (*AgentAuthService, error) {
    caCert, err := ioutil.ReadFile(caCertPath)
    if err != nil {
        return nil, err
    }
    
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    
    return &AgentAuthService{
        caCertPool: caCertPool,
        agentDB:    agentDB,
    }, nil
}

func (aas *AgentAuthService) ValidateAgentCertificate(r *http.Request) (*Agent, error) {
    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
        return nil, fmt.Errorf("no client certificate provided")
    }
    
    clientCert := r.TLS.PeerCertificates[0]
    
    // Verify certificate chain
    opts := x509.VerifyOptions{
        Roots: aas.caCertPool,
    }
    
    _, err := clientCert.Verify(opts)
    if err != nil {
        return nil, fmt.Errorf("certificate verification failed: %v", err)
    }
    
    // Extract agent ID from certificate
    agentID := clientCert.Subject.CommonName
    
    // Validate agent exists and is active
    agent, err := aas.agentDB.GetAgent(agentID)
    if err != nil {
        return nil, fmt.Errorf("agent not found: %v", err)
    }
    
    if !agent.Active {
        return nil, fmt.Errorf("agent is inactive")
    }
    
    return agent, nil
}

type Agent struct {
    ID          string    `json:"id"`
    Hostname    string    `json:"hostname"`
    IPAddress   string    `json:"ip_address"`
    OS          string    `json:"os"`
    Version     string    `json:"version"`
    Active      bool      `json:"active"`
    LastSeen    time.Time `json:"last_seen"`
    Certificate string    `json:"certificate"`
}
```

### 5.2 API Key Management for Agent Registration

```go
// internal/agent/apikey.go
package agent

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "time"
)

type APIKeyService struct {
    storage APIKeyStorage
}

type APIKey struct {
    ID        string    `json:"id"`
    Key       string    `json:"key"`
    Hash      string    `json:"hash"`
    AgentID   string    `json:"agent_id"`
    CreatedAt time.Time `json:"created_at"`
    ExpiresAt time.Time `json:"expires_at"`
    Active    bool      `json:"active"`
    LastUsed  time.Time `json:"last_used"`
}

func NewAPIKeyService(storage APIKeyStorage) *APIKeyService {
    return &APIKeyService{storage: storage}
}

func (aks *APIKeyService) GenerateAPIKey(agentID string, expiryDuration time.Duration) (*APIKey, error) {
    keyBytes := make([]byte, 32)
    if _, err := rand.Read(keyBytes); err != nil {
        return nil, err
    }
    
    key := hex.EncodeToString(keyBytes)
    hash := sha256.Sum256([]byte(key))
    
    apiKey := &APIKey{
        ID:        generateID(),
        Key:       key,
        Hash:      hex.EncodeToString(hash[:]),
        AgentID:   agentID,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(expiryDuration),
        Active:    true,
    }
    
    if err := aks.storage.StoreAPIKey(apiKey); err != nil {
        return nil, err
    }
    
    return apiKey, nil
}

func (aks *APIKeyService) ValidateAPIKey(key string) (*APIKey, error) {
    hash := sha256.Sum256([]byte(key))
    hashString := hex.EncodeToString(hash[:])
    
    apiKey, err := aks.storage.GetAPIKeyByHash(hashString)
    if err != nil {
        return nil, err
    }
    
    if !apiKey.Active {
        return nil, fmt.Errorf("API key is inactive")
    }
    
    if time.Now().After(apiKey.ExpiresAt) {
        return nil, fmt.Errorf("API key has expired")
    }
    
    // Update last used timestamp
    apiKey.LastUsed = time.Now()
    aks.storage.UpdateAPIKey(apiKey)
    
    return apiKey, nil
}
```

## 6. Audit Logging and Security Monitoring

### 6.1 Comprehensive Audit Logging

```go
// internal/audit/logger.go
package audit

import (
    "context"
    "encoding/json"
    "time"
    
    "github.com/sirupsen/logrus"
)

type AuditLogger struct {
    logger  *logrus.Logger
    storage AuditStorage
}

type AuditEvent struct {
    ID          string                 `json:"id"`
    Timestamp   time.Time             `json:"timestamp"`
    UserID      string                `json:"user_id"`
    Username    string                `json:"username"`
    Action      string                `json:"action"`
    Resource    string                `json:"resource"`
    ResourceID  string                `json:"resource_id"`
    IPAddress   string                `json:"ip_address"`
    UserAgent   string                `json:"user_agent"`
    Success     bool                  `json:"success"`
    Error       string                `json:"error,omitempty"`
    Details     map[string]interface{} `json:"details"`
    SessionID   string                `json:"session_id"`
}

func NewAuditLogger(storage AuditStorage) *AuditLogger {
    logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{})
    
    return &AuditLogger{
        logger:  logger,
        storage: storage,
    }
}

func (al *AuditLogger) LogEvent(ctx context.Context, event AuditEvent) {
    event.ID = generateID()
    event.Timestamp = time.Now()
    
    // Log to structured logger
    al.logger.WithFields(logrus.Fields{
        "audit_id":    event.ID,
        "user_id":     event.UserID,
        "action":      event.Action,
        "resource":    event.Resource,
        "success":     event.Success,
        "ip_address":  event.IPAddress,
    }).Info("Audit event")
    
    // Store in database for querying
    if err := al.storage.StoreAuditEvent(ctx, event); err != nil {
        al.logger.WithError(err).Error("Failed to store audit event")
    }
}

// Predefined audit actions
const (
    ActionLogin              = "user.login"
    ActionLogout             = "user.logout"
    ActionPasswordChange     = "user.password_change"
    ActionMFAEnable         = "user.mfa_enable"
    ActionMFADisable        = "user.mfa_disable"
    ActionViewDashboard     = "dashboard.view"
    ActionViewAlert         = "alert.view"
    ActionAcknowledgeAlert  = "alert.acknowledge"
    ActionCreateInvestigation = "investigation.create"
    ActionViewAgent         = "agent.view"
    ActionDeployAgent       = "agent.deploy"
    ActionConfigChange      = "system.config_change"
)
```

### 6.2 Security Event Detection

```go
// internal/security/detector.go
package security

import (
    "context"
    "time"
)

type SecurityDetector struct {
    auditStorage AuditStorage
    alertManager AlertManager
}

type SecurityRule struct {
    ID          string        `json:"id"`
    Name        string        `json:"name"`
    Description string        `json:"description"`
    Condition   string        `json:"condition"`
    Threshold   int           `json:"threshold"`
    TimeWindow  time.Duration `json:"time_window"`
    Severity    string        `json:"severity"`
    Enabled     bool          `json:"enabled"`
}

var DefaultSecurityRules = []SecurityRule{
    {
        ID:          "failed_login_attempts",
        Name:        "Multiple Failed Login Attempts",
        Description: "Detect multiple failed login attempts from same IP",
        Condition:   "action = 'user.login' AND success = false",
        Threshold:   5,
        TimeWindow:  15 * time.Minute,
        Severity:    "high",
        Enabled:     true,
    },
    {
        ID:          "privilege_escalation",
        Name:        "Privilege Escalation Attempt",
        Description: "Detect attempts to access resources without permission",
        Condition:   "success = false AND error LIKE '%permission%'",
        Threshold:   3,
        TimeWindow:  5 * time.Minute,
        Severity:    "critical",
        Enabled:     true,
    },
    {
        ID:          "unusual_access_pattern",
        Name:        "Unusual Access Pattern",
        Description: "Detect access from unusual locations or times",
        Condition:   "action = 'user.login' AND success = true",
        Threshold:   1,
        TimeWindow:  24 * time.Hour,
        Severity:    "medium",
        Enabled:     true,
    },
}

func (sd *SecurityDetector) EvaluateRules(ctx context.Context) error {
    for _, rule := range DefaultSecurityRules {
        if !rule.Enabled {
            continue
        }
        
        events, err := sd.auditStorage.QueryEvents(ctx, rule.Condition, rule.TimeWindow)
        if err != nil {
            continue
        }
        
        if len(events) >= rule.Threshold {
            alert := SecurityAlert{
                RuleID:      rule.ID,
                RuleName:    rule.Name,
                Severity:    rule.Severity,
                EventCount:  len(events),
                TimeWindow:  rule.TimeWindow,
                Events:      events,
                DetectedAt:  time.Now(),
            }
            
            sd.alertManager.CreateSecurityAlert(ctx, alert)
        }
    }
    
    return nil
}
```

## 7. Secrets Management

### 7.1 HashiCorp Vault Integration

```go
// internal/secrets/vault.go
package secrets

import (
    "context"
    "fmt"
    
    "github.com/hashicorp/vault/api"
)

type VaultSecretManager struct {
    client *api.Client
    mount  string
}

func NewVaultSecretManager(address, token, mount string) (*VaultSecretManager, error) {
    config := api.DefaultConfig()
    config.Address = address
    
    client, err := api.NewClient(config)
    if err != nil {
        return nil, err
    }
    
    client.SetToken(token)
    
    return &VaultSecretManager{
        client: client,
        mount:  mount,
    }, nil
}

func (vsm *VaultSecretManager) GetSecret(ctx context.Context, path string) (map[string]interface{}, error) {
    secret, err := vsm.client.Logical().Read(fmt.Sprintf("%s/data/%s", vsm.mount, path))
    if err != nil {
        return nil, err
    }
    
    if secret == nil {
        return nil, fmt.Errorf("secret not found")
    }
    
    data, ok := secret.Data["data"].(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid secret format")
    }
    
    return data, nil
}

func (vsm *VaultSecretManager) StoreSecret(ctx context.Context, path string, data map[string]interface{}) error {
    secretData := map[string]interface{}{
        "data": data,
    }
    
    _, err := vsm.client.Logical().Write(fmt.Sprintf("%s/data/%s", vsm.mount, path), secretData)
    return err
}
```

## 8. Security Headers and CORS

### 8.1 Security Headers Middleware

```go
// internal/middleware/security.go
package middleware

import (
    "github.com/gin-gonic/gin"
)

func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Prevent clickjacking
        c.Header("X-Frame-Options", "DENY")
        
        // Prevent MIME type sniffing
        c.Header("X-Content-Type-Options", "nosniff")
        
        // Enable XSS protection
        c.Header("X-XSS-Protection", "1; mode=block")
        
        // Strict Transport Security
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        
        // Content Security Policy
        c.Header("Content-Security-Policy", 
            "default-src 'self'; "+
            "script-src 'self' 'unsafe-inline'; "+
            "style-src 'self' 'unsafe-inline'; "+
            "img-src 'self' data:; "+
            "connect-src 'self' ws: wss:; "+
            "font-src 'self'")
        
        // Referrer Policy
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // Permissions Policy
        c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        
        c.Next()
    }
}

func CORS() gin.HandlerFunc {
    return func(c *gin.Context) {
        origin := c.Request.Header.Get("Origin")
        
        // Define allowed origins
        allowedOrigins := []string{
            "https://musafir-ui.local",
            "https://localhost:3000",
        }
        
        for _, allowedOrigin := range allowedOrigins {
            if origin == allowedOrigin {
                c.Header("Access-Control-Allow-Origin", origin)
                break
            }
        }
        
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
        c.Header("Access-Control-Allow-Credentials", "true")
        c.Header("Access-Control-Max-Age", "86400")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    }
}
```

## 9. Security Configuration

### 9.1 Environment-based Security Configuration

```yaml
# config/security.yaml
security:
  jwt:
    private_key_path: "/etc/musafir/keys/jwt-private.pem"
    public_key_path: "/etc/musafir/keys/jwt-public.pem"
    issuer: "musafir-platform"
    expiry: "24h"
  
  tls:
    cert_file: "/etc/musafir/certs/server.crt"
    key_file: "/etc/musafir/certs/server.key"
    ca_file: "/etc/musafir/certs/ca.crt"
    min_version: "1.2"
  
  encryption:
    key_file: "/etc/musafir/keys/encryption.key"
    algorithm: "AES-256-GCM"
  
  session:
    timeout: "24h"
    secure: true
    http_only: true
    same_site: "strict"
  
  mfa:
    issuer: "MUSAFIR SecOps"
    window_size: 1
    
  rate_limiting:
    login_attempts: 5
    login_window: "15m"
    api_requests: 1000
    api_window: "1h"
  
  audit:
    enabled: true
    retention: "2y"
    sensitive_fields:
      - "password"
      - "token"
      - "secret"
```

This comprehensive security specification ensures that the MUSAFIR platform maintains the highest security standards for protecting sensitive security data and providing secure access to EDR, XDR, and SIEM capabilities.