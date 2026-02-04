# Architecture Documentation

## POC 15: Beeldbeschikbaarheid - Option A Architecture

### Overview

POC 15 demonstrates secure healthcare image exchange in the Netherlands using the NEN 7541 standard. The implementation follows the **Option A architecture**, which uses an intermediary Identity Provider (IDP) to manage authentication and token exchange.

### Key Components

```
┌──────────────┐
│   User       │
│ (Healthcare  │
│  Provider)   │
└──────┬───────┘
       │ 1. Authenticate
       ↓
┌──────────────┐
│     DEZI     │ OpenID Connect
│  (Auth       │ + PKCE
│   Platform)  │
└──────┬───────┘
       │ 2. Access Token
       │    + DEZI Claims
       ↓
┌──────────────┐
│     IDP      │ Token Exchange
│  (Identity   │ (OAuth 2.0)
│   Provider)  │
└──────┬───────┘
       │ 3. Auth-Token
       │    (Signed JWT)
       ↓
┌──────────────┐
│    PACS      │ DICOMweb
│  (Source     │ QIDO-RS
│   System)    │ WADO-RS
└──────────────┘
```

### Authentication Flow

1. **DEZI Authentication (OIDC with PKCE)**
   - User initiates login via healthcare system
   - Generate PKCE parameters (code verifier & challenge)
   - Redirect to DEZI authorization endpoint
   - User authenticates with chosen method (UZI-pas, DigiD, EUDI wallet, etc.)
   - DEZI returns authorization code
   - Exchange code for access token (with PKCE verification)
   - Retrieve UserInfo with DEZI declaration (encrypted JWE)

2. **Token Exchange (Option A)**
   - Healthcare system stores access token with IDP
   - When accessing a source, request auth-token from IDP
   - IDP validates access token
   - IDP generates signed auth-token (JWT) with BIG credentials
   - Auth-token valid for 5 minutes for specific resource

3. **Image Access (DICOMweb)**
   - Client requests images from PACS with auth-token
   - PACS validates auth-token signature (via public key registry)
   - PACS performs authorization check (ITI-102)
   - PACS returns images via WADO-RS or search results via QIDO-RS

### Token Types

#### Access Token
- **Purpose**: Authentication with IDP
- **Lifetime**: 1 hour
- **Scope**: Internal to IDP
- **Contains**: Reference to DEZI claims

#### Auth-Token (JWT)
- **Purpose**: Authorization at source systems
- **Lifetime**: 5 minutes
- **Scope**: Specific resource (PACS URL)
- **Contains**:
  - BIG registration number
  - BIG role code
  - URA (organization identifier)
  - Healthcare provider name
  - Authentication timestamp
  - Target resource URL

### Security Features

1. **PKCE (Proof Key for Code Exchange)**
   - Prevents authorization code interception
   - Required for all OIDC flows

2. **Token Signatures**
   - All auth-tokens signed with RS256
   - Public keys published via JWKS endpoint
   - Source systems verify signatures before granting access

3. **Short-lived Tokens**
   - Auth-tokens expire after 5 minutes
   - Minimizes risk of token replay attacks

4. **Audience Restriction**
   - Auth-tokens scoped to specific resources
   - Cannot be reused for different sources

### IHE Profiles Implemented

- **ITI-71**: Get Access Token (Authorization Code Flow)
- **ITI-72**: Incorporate Access Token (Bearer token in requests)
- **ITI-102**: Introspect Access Token (Authorization decisions)

### Standards Compliance

- **NEN 7541:2026**: Dutch standard for radiology image exchange
- **OpenID Connect 1.0**: Identity layer
- **OAuth 2.0 (RFC 6749)**: Authorization framework
- **PKCE (RFC 7636)**: Code exchange security
- **JWT/JWS (RFC 7519/7515)**: Token format and signing
- **DICOMweb**: QIDO-RS, WADO-RS for image access

### Why Option A?

Option A was chosen over Option B (direct authentication token forwarding) because:

1. **Future-proof**: Abstracts away authentication method complexity
2. **Standardization**: Single auth-token format for all sources
3. **Scalability**: Easy to add new authentication methods
4. **Simplicity**: Sources don't need to support multiple auth formats

### Production Considerations

For production deployment, the following must be addressed:

1. **Configuration Management**
   - Use `config.yaml` to externalize all secrets and URLs
   - Override sensitive values via environment variables
   - Never commit `config.yaml` with production secrets

2. **IDP Certification**
   - Governance model for IDP certification
   - Trust framework and liability
   - Audit and compliance requirements

3. **Public Key Registry**
   - Centralized JWKS endpoint
   - Key rotation procedures
   - Revocation mechanisms

4. **Encryption**
   - JWE for UserInfo responses
   - TLS 1.3 for all communications
   - Hardware security modules (HSM) for key storage

5. **Consent and Localization**
   - Integration with Mitz (patient consent)
   - Localization service (where is data?)

6. **Observability**
   - Enable HTTP request logging (`logging.http_requests: true`)
   - Integrate with centralized logging (ELK, Loki, etc.)
   - Add metrics and tracing (OpenTelemetry)
