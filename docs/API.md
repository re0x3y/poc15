# API Documentation

## Configuration

POC 15 uses YAML configuration. Copy `config.example.yaml` to `config.yaml`:

```bash
cp config.example.yaml config.yaml
```

Run with custom config:

```bash
go run ./cmd/server -config=config.yaml
```

## DEZI Client

### Creating a Client

```go
import "github.com/reoxey/poc15/dezi"

// Basic client with defaults
client, err := dezi.NewClient(&dezi.Config{
    Issuer:      "https://auth.dezi.nl",
    ClientID:    "your-client-id",
    RedirectURI: "https://your-app.nl/callback",
    Scopes:      []string{"openid"},
})

// Client with custom options (recommended)
client, err := dezi.NewClientWithConfig(&dezi.Config{
    Issuer:      "https://auth.dezi.nl",
    ClientID:    "your-client-id",
    RedirectURI: "https://your-app.nl/callback",
    Scopes:      []string{"openid"},
}, &dezi.ClientOptions{
    HTTPTimeout:           30 * time.Second,
    TokenExchangeResource: "https://auth.dezi.nl",
    IntrospectURL:         "https://auth.dezi.nl/introspect",
    LogHTTPRequests:       true,
})
```

### Authentication Flow

```go
// 1. Generate PKCE parameters
pkce, err := dezi.GeneratePKCE()

// 2. Get authorization URL
authURL, err := client.GetAuthorizationURL(state, pkce)
// Redirect user to authURL

// 3. Handle callback and exchange code
tokenResp, err := client.ExchangeCode(code, pkce)

// 4. Get user info and DEZI claims
claims, err := client.GetUserInfo(tokenResp.AccessToken)
```

## IDP Service

### Creating an IDP

```go
import "github.com/reoxey/poc15/idp"

service, err := idp.NewService(&idp.Config{
    Issuer:         "https://idp.example.nl",
    AuthTokenTTL:   5 * time.Minute,
    AccessTokenTTL: 1 * time.Hour,
})
```

### Token Exchange

```go
// Store access token from DEZI
service.StoreAccessToken(accessToken, deziClaims)

// Exchange for auth-token when accessing a resource
authToken, err := service.ExchangeToken(accessToken, "https://pacs.hospital.nl")

// Validate auth-token (typically done by source system)
claims, err := service.ValidateAuthToken(authToken)
```

## Authorization Server

### Creating an Authorization Server

```go
import "github.com/reoxey/poc15/authz"

server := authz.NewServer(&authz.Config{
    Issuer:         "https://authz.example.nl",
    AuthCodeTTL:    10 * time.Minute,
    AccessTokenTTL: 1 * time.Hour,
})
```

### Authorization Code Flow (ITI-71)

```go
// Create authorization
auth, err := server.CreateAuthorization(
    clientID,
    redirectURI,
    scope,
    subject,
    codeVerifier,
)

// Exchange code for token
tokenResp, err := server.ExchangeAuthorizationCode(
    code,
    clientID,
    redirectURI,
    codeVerifier,
)
```

### Token Introspection (ITI-102)

```go
// Introspect token
introspection, err := server.IntrospectToken(token)

// Perform authorization decision
decision, err := server.PerformAuthorizationDecision(
    token,
    "ImagingStudy",
    "read",
)
```

## DICOMweb Client

### Creating a Client

```go
import "github.com/reoxey/poc15/dicomweb"

client := dicomweb.NewClient(
    "https://pacs.hospital.nl",
    func(resource string) (string, error) {
        return idpService.ExchangeToken(accessToken, resource)
    },
)
```

### Searching for Studies (QIDO-RS)

```go
studies, err := client.SearchStudies("patient-001")
for _, study := range studies {
    fmt.Printf("Study: %s (%s)\n", study.StudyDescription, study.Modality)
}
```

### Retrieving Images (WADO-RS)

```go
// Retrieve complete study
data, err := client.RetrieveStudy(studyInstanceUID)

// Retrieve metadata only
metadata, err := client.RetrieveMetadata(studyInstanceUID)
```

## DICOMweb Server

### Creating a Server

```go
import "github.com/reoxey/poc15/dicomweb"

// Basic server with defaults
server := dicomweb.NewServer(
    "https://pacs.hospital.nl",
    idpService,
    authzServer,
)

// Server with custom configuration (recommended)
server := dicomweb.NewServerWithConfig(
    "https://pacs.hospital.nl",
    idpService,
    authzServer,
    &dicomweb.ServerConfig{
        BearerTokenTTL:    1 * time.Hour,
        BearerTokenSecret: "your-secret-key",
        CleanupInterval:   5 * time.Minute,
    },
)

// Register HTTP handlers
mux := http.NewServeMux()
server.RegisterHandlers(mux)

// Optional: Add HTTP request logging middleware
handler := httputil.LoggingMiddleware(mux, true)

// Start server
http.ListenAndServe(":8083", handler)
```

### Endpoints

- `GET /studies?PatientID=xxx` - QIDO-RS search
- `GET /studies/{studyUID}` - WADO-RS retrieve study
- `GET /studies/{studyUID}/metadata` - Retrieve metadata

All endpoints require Bearer token authentication with auth-token.

## Data Models

### DEZI Claims

```go
type DeziClaims struct {
    BIGNumber        string // "49001234567"
    BIGRoleCode      string // "01.015" (Radioloog)
    URA              string // "90001234"
    OrganizationName string // "Amsterdam UMC"
    GivenName        string // "Jan"
    FamilyName       string // "de Vries"
    AuthTime         int64  // Unix timestamp
}
```

### Auth-Token Claims

```go
type AuthTokenClaims struct {
    BIGNumber        string
    BIGRoleCode      string
    URA              string
    OrganizationName string
    GivenName        string
    FamilyName       string
    AuthTime         int64
    TargetResource   string // URL of source system
}
```

### Imaging Study

```go
type ImagingStudy struct {
    StudyInstanceUID string
    PatientID        string
    StudyDate        time.Time
    StudyDescription string
    Modality         string // "CT", "MR", "XR", etc.
    AccessionNumber  string
    NumberOfSeries   int
    NumberOfImages   int
}
```

## Error Handling

All functions return standard Go errors. Check for errors and handle appropriately:

```go
if err != nil {
    log.Printf("Operation failed: %v", err)
    return err
}
```

Common error scenarios:
- Invalid or expired tokens
- Network failures
- Authorization denied
- Invalid request parameters

## HTTP Logging

Enable HTTP request logging for debugging:

```go
import "github.com/reoxey/poc15/internal/httputil"

// For HTTP clients (outgoing requests)
client := httputil.NewLoggingClient(30*time.Second, true)

// For HTTP servers (incoming requests)
handler := httputil.LoggingMiddleware(mux, true)
```

Output format: `[METHOD URL]`

Example:
```
[GET https://auth.dezi.nl/.well-known/openid-configuration]
[POST https://auth.dezi.nl/token]
```

## Internal Packages

### internal/config

Configuration management with YAML support:

```go
import "github.com/reoxey/poc15/internal/config"

cfg, err := config.Load("config.yaml")
// Access: cfg.Server, cfg.IDP, cfg.Dezi, cfg.DICOMweb, etc.
```

### internal/crypto

Cryptographic utilities:

```go
import "github.com/reoxey/poc15/internal/crypto"

// Generate URL-safe random token
token, err := crypto.GenerateURLSafeToken(32)

// Generate random string
str, err := crypto.GenerateRandomString(16)
```

### internal/httputil

HTTP utilities for JSON responses and logging:

```go
import "github.com/reoxey/poc15/internal/httputil"

// JSON responses
httputil.WriteJSON(w, http.StatusOK, data)
httputil.WriteBadRequest(w, "error", "description")
httputil.WriteUnauthorized(w, "error", "description")

// Extract bearer token from request
token, err := httputil.ExtractBearerToken(r)
```
