# Quick Start Guide

## Installation

```bash
git clone https://github.com/reoxey/poc15.git
cd poc15
make deps
```

## Building

```bash
make build
```

This creates the binary:
- `bin/poc15-server` - HTTP server demonstration

## Configuration

Create the configuration file:

```bash
make config
```

Key configuration options in `config.yaml`:
- `dezi.issuer`, `dezi.client_id`, `dezi.client_secret` - DEZI credentials
- `dicomweb.bearer_token_secret` - Secret for signing tokens (change in production!)
- `logging.http_requests` - Enable HTTP request logging

## Running the Demo

```bash
make run
```

This builds (if needed), creates config (if missing), and starts the HTTP servers:
- **PACS (DICOMweb)**: `http://localhost:8083`

Then runs the complete authentication and authorization flow.

## Running Tests

```bash
make test
```

## Project Structure

```
poc15/
├── authz/           # OAuth 2.0 authorization server (ITI-71, ITI-72, ITI-102)
├── cmd/
│   └── server/      # Full HTTP server demo
├── config.example.yaml  # Example configuration file
├── dezi/            # DEZI OpenID Connect client
├── dicomweb/        # DICOMweb client and server
├── docs/            # Documentation
│   ├── API.md
│   └── ARCHITECTURE.md
├── idp/             # Identity Provider (token exchange)
├── internal/        # Shared internal packages
│   ├── config/      # YAML configuration loading
│   ├── crypto/      # Cryptographic utilities
│   └── httputil/    # HTTP helpers and logging
├── mock/            # Mock DEZI server for testing
├── models/          # Data models and JWT claims
├── go.mod
├── Makefile
└── README.md
```

## Example Usage

### Authenticate with DEZI

```go
import "github.com/reoxey/poc15/dezi"

// Basic client
client, _ := dezi.NewClient(&dezi.Config{
    Issuer:      "https://auth.dezi.nl",
    ClientID:    "your-client-id",
    RedirectURI: "https://your-app/callback",
})

// Or with custom options (HTTP logging, timeouts)
client, _ := dezi.NewClientWithConfig(&dezi.Config{
    Issuer:      "https://auth.dezi.nl",
    ClientID:    "your-client-id",
    RedirectURI: "https://your-app/callback",
}, &dezi.ClientOptions{
    HTTPTimeout:     30 * time.Second,
    LogHTTPRequests: true,
})

pkce, _ := dezi.GeneratePKCE()
authURL, _ := client.GetAuthorizationURL(state, pkce)
// Redirect user to authURL

// After callback:
tokens, _ := client.ExchangeCode(code, pkce)
claims, _ := client.GetUserInfo(tokens.AccessToken)
```

### Exchange Tokens (Option A)

```go
import "github.com/reoxey/poc15/idp"

idpService, _ := idp.NewService(&idp.Config{
    Issuer: "https://idp.example.nl",
})

// Store DEZI access token
idpService.StoreAccessToken(accessToken, deziClaims)

// Get auth-token for specific resource
authToken, _ := idpService.ExchangeToken(
    accessToken,
    "https://pacs.hospital.nl",
)
```

### Access Images via DICOMweb

```go
import "github.com/reoxey/poc15/dicomweb"

client := dicomweb.NewClient(
    "https://pacs.hospital.nl",
    getAuthTokenFunc,
)

// Search for studies
studies, _ := client.SearchStudies("patient-001")

// Retrieve study
data, _ := client.RetrieveStudy(studyUID)
```

## Standards Reference

- **NEN 7541:2026**: Dutch standard for radiology image exchange
- **OpenID Connect 1.0**: https://openid.net/specs/openid-connect-core-1_0.html
- **OAuth 2.0 (RFC 6749)**: https://www.rfc-editor.org/rfc/rfc6749
- **PKCE (RFC 7636)**: https://www.rfc-editor.org/rfc/rfc7636
- **JWT (RFC 7519)**: https://www.rfc-editor.org/rfc/rfc7519
- **JWS (RFC 7515)**: https://www.rfc-editor.org/rfc/rfc7515
- **IHE IUA**: https://profiles.ihe.net/ITI/IUA/
- **DICOMweb**: https://www.dicomstandard.org/using/dicomweb

## Architecture Overview

```
User → DEZI (OIDC) → Access Token
         ↓
    IDP Service → Auth-Token (JWT)
         ↓
    PACS/VNA → Images (DICOMweb)
```

**Option A Architecture**: IDP acts as intermediary between authentication (DEZI) and authorization (source systems). Provides a standardized auth-token format regardless of authentication method used.

## Next Steps

1. Review the [Architecture Documentation](docs/ARCHITECTURE.md)
2. Check the [API Documentation](docs/API.md)
3. Explore the code in each package
4. Run the demos and tests
5. Modify for your specific use case

## License

MIT
