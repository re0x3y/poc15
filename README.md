# POC 15 - Beeldbeschikbaarheid (Image Availability)

This is a Proof of Concept implementation in Go for POC 15, which demonstrates healthcare image exchange in the Netherlands using:

- **NEN 7541** standard for radiology image exchange
- **DEZI authentication** via OpenID Connect (OIDC)
- **OAuth 2.0** authorization with IHE IUA profile
- **DICOMweb** for image retrieval
- **Token Exchange** mechanism (Option A architecture)

## Architecture

The POC implements the Option A architecture where:

1. Healthcare providers authenticate via DEZI (OpenID Connect)
2. An Identity Provider (IDP) manages authentication and issues auth-tokens
3. Source systems validate auth-tokens for image access
4. Two-token system: access tokens (IDP ↔ client) and auth-tokens (client ↔ source)

## Components

- `dezi/` - DEZI OpenID Connect client implementation
- `idp/` - Identity Provider with token exchange service
- `authz/` - Authorization server (ITI-71, ITI-72, ITI-102)
- `dicomweb/` - DICOMweb client and server stubs
- `models/` - Common data models and JWT claims
- `cmd/` - Main applications and demos
- `internal/` - Shared utilities
  - `config/` - YAML configuration management
  - `crypto/` - Cryptographic utilities
  - `httputil/` - HTTP helpers and logging

## Configuration

Create the configuration file:

```bash
make config
```

Or manually:

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` to set:
- Server addresses and timeouts
- DEZI credentials (issuer, client_id, client_secret)
- Token TTLs and secrets
- HTTP request logging

## Running the POC

```bash
# Install dependencies
make deps

# Build and run (creates config.yaml if missing)
make run

# Or build only
make build

# Run with custom config
./bin/poc15-server -config=/path/to/config.yaml

# Run tests
make test
```

See `make help` for all available targets.

## Technical Details

### Authentication Flow

1. User initiates login via healthcare system
2. OIDC Authorization Code Flow with PKCE to DEZI
3. Exchange authorization code for access token
4. Retrieve UserInfo and DEZI declaration (signed JWT)
5. Store access token for future use

### Authorization Flow (Option A)

1. Client requests auth-token from IDP (using access token)
2. IDP validates access token and generates signed auth-token
3. Client uses auth-token to request images from source
4. Source validates auth-token signature via public key registry
5. Source performs authorization check (ITI-102)
6. Source returns images via DICOMweb

### Token Format

Auth-tokens are JWTs containing:
- BIG registration number
- BIG role code
- URA (organization identifier)
- Authentication timestamp
- Expiration time

## Standards Implemented

- OpenID Connect 1.0
- OAuth 2.0 (RFC 6749)
- PKCE (RFC 7636)
- JWT (RFC 7519), JWS (RFC 7515), JWE (RFC 7516)
- IHE IUA (ITI-71, ITI-72, ITI-102)
- DICOMweb (WADO-RS, QIDO-RS)

## License

AGPL-3.0 license
