// Package dezi provides a DEZI OpenID Connect client implementation.
package dezi

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/reoxey/poc15/internal/config"
	"github.com/reoxey/poc15/internal/crypto"
	"github.com/reoxey/poc15/internal/httputil"
	"github.com/reoxey/poc15/models"
)

// Default configuration values.
const (
	defaultHTTPTimeout  = 30 * time.Second
	pkceVerifierByteLen = 32
	discoveryPath       = "/.well-known/openid-configuration"
	contentTypeForm     = "application/x-www-form-urlencoded"
)

// Common errors.
var (
	ErrMetadataNotLoaded    = errors.New("OIDC metadata not loaded")
	ErrUserInfoNotAvailable = errors.New("userinfo endpoint not available")
	ErrTokenInactive        = errors.New("token is not active")
	ErrTokenExpired         = errors.New("token has expired")
	ErrInvalidToken         = errors.New("token is not valid")
	ErrMissingKeyInfo       = errors.New("token header missing both 'kid' and 'x5c' fields")
)

// Client represents a DEZI OpenID Connect client.
type Client struct {
	config                *Config
	options               *ClientOptions
	oidcMetadata          *models.OIDCConfig
	httpClient            *http.Client
	tokenExchangeResource string
	introspectURL         string
}

// Config holds the DEZI client configuration.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// ClientOptions holds optional client configuration.
type ClientOptions struct {
	HTTPTimeout           time.Duration
	TokenExchangeResource string
	IntrospectURL         string
	LogHTTPRequests       bool
	IHEIUA                config.IHEIUAConfig
}

// PKCEParams holds PKCE challenge parameters.
type PKCEParams struct {
	CodeVerifier  string
	CodeChallenge string
	Method        string
}

// NewClient creates a new DEZI OIDC client with default options.
func NewClient(cfg *Config) (*Client, error) {
	return NewClientWithConfig(cfg, nil)
}

// NewClientWithConfig creates a new DEZI OIDC client with custom options.
func NewClientWithConfig(cfg *Config, opts *ClientOptions) (*Client, error) {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid"}
	}

	if opts == nil {
		opts = &ClientOptions{}
	}

	if opts.HTTPTimeout == 0 {
		opts.HTTPTimeout = defaultHTTPTimeout
	}

	// Derive default URLs from issuer if not provided
	issuerBase := strings.TrimSuffix(cfg.Issuer, "/")
	tokenExchangeResource := opts.TokenExchangeResource
	if tokenExchangeResource == "" {
		tokenExchangeResource = issuerBase
	}
	introspectURL := opts.IntrospectURL
	if introspectURL == "" {
		introspectURL = issuerBase + "/introspect"
	}

	client := &Client{
		config:                cfg,
		options:               opts,
		httpClient:            httputil.NewLoggingClient(opts.HTTPTimeout, opts.LogHTTPRequests),
		tokenExchangeResource: tokenExchangeResource,
		introspectURL:         introspectURL,
	}

	if err := client.fetchMetadata(); err != nil {
		return nil, fmt.Errorf("fetching OIDC metadata: %w", err)
	}

	return client, nil
}

// fetchMetadata retrieves OpenID Connect Discovery metadata.
func (c *Client) fetchMetadata() error {
	discoveryURL := strings.TrimSuffix(c.config.Issuer, "/") + discoveryPath

	resp, err := c.httpClient.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var metadata models.OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return fmt.Errorf("decoding discovery document: %w", err)
	}

	c.oidcMetadata = &metadata
	c.logDiscovery()

	return nil
}

func (c *Client) logDiscovery() {
	log.Printf("OIDC Discovery completed:")
	log.Printf("  Issuer: %s", c.oidcMetadata.Issuer)
	log.Printf("  Authorization: %s", c.oidcMetadata.AuthorizationEndpoint)
	log.Printf("  Token: %s", c.oidcMetadata.TokenEndpoint)
	log.Printf("  UserInfo: %s", c.oidcMetadata.UserInfoEndpoint)
	log.Printf("  JWKS: %s", c.oidcMetadata.JWKSUri)
}

// GeneratePKCE generates PKCE parameters for secure authorization.
func GeneratePKCE() (*PKCEParams, error) {
	verifier, err := crypto.GenerateURLSafeToken(pkceVerifierByteLen)
	if err != nil {
		return nil, fmt.Errorf("generating code verifier: %w", err)
	}

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEParams{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        "S256",
	}, nil
}

// GetAuthorizationURL generates the authorization URL for the OIDC flow.
func (c *Client) GetAuthorizationURL(state string, pkce *PKCEParams) (string, error) {
	if c.oidcMetadata == nil {
		return "", ErrMetadataNotLoaded
	}

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {c.config.ClientID},
		"redirect_uri":  {c.config.RedirectURI},
		"scope":         {strings.Join(c.config.Scopes, " ")},
		"state":         {state},
	}

	if pkce != nil {
		params.Set("code_challenge", pkce.CodeChallenge)
		params.Set("code_challenge_method", pkce.Method)
	}

	return c.oidcMetadata.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for tokens.
func (c *Client) ExchangeCode(code, codeVerifier string) (*models.TokenResponse, error) {
	if c.oidcMetadata == nil {
		return nil, ErrMetadataNotLoaded
	}

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.config.RedirectURI},
		"client_id":    {c.config.ClientID},
	}

	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	return c.postTokenRequest(c.oidcMetadata.TokenEndpoint, data)
}

// ExchangeToken performs token exchange to get IHE IUA tokens.
func (c *Client) ExchangeToken(accessToken string) (*models.TokenResponse, error) {
	if c.oidcMetadata == nil {
		return nil, ErrMetadataNotLoaded
	}

	authzDetails := c.buildAuthorizationDetails()

	data := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"resource":              {c.tokenExchangeResource},
		"requested_token_type":  {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":         {accessToken},
		"subject_token_type":    {"urn:ietf:params:oauth:token-type:access_token"},
		"authorization_details": {authzDetails},
	}

	return c.postTokenRequest(c.oidcMetadata.TokenEndpoint, data)
}

// buildAuthorizationDetails builds the IHE IUA authorization_details JSON.
func (c *Client) buildAuthorizationDetails() string {
	if c.options == nil || c.options.IHEIUA.TID == "" {
		return `[{"type":"ihe_iua","tid":"urn:oid:2.16.528.1.1007.3.3.33568149","person_id":"urn:oid:2.16.840.1.113883.2.4.6.3.111222333","purpose_of_use":[{"system":"http://terminology.hl7.org/CodeSystem/v3-ActReason","code":"TREAT"}]}]`
	}

	return fmt.Sprintf(`[{"type":"ihe_iua","tid":"%s","person_id":"%s","purpose_of_use":[{"system":"%s","code":"%s"}]}]`,
		c.options.IHEIUA.TID,
		c.options.IHEIUA.PersonID,
		c.options.IHEIUA.PurposeOfUse.System,
		c.options.IHEIUA.PurposeOfUse.Code,
	)
}

// postTokenRequest sends a POST request to the token endpoint.
func (c *Client) postTokenRequest(endpoint string, data url.Values) (*models.TokenResponse, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeForm)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp models.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &tokenResp, nil
}

// TokenIntrospect performs token introspection.
func (c *Client) TokenIntrospect(accessToken, clientID, secret string) error {
	req, err := http.NewRequest(http.MethodPost, c.introspectURL, strings.NewReader("token="+accessToken))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeForm)
	req.SetBasicAuth(clientID, secret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("introspect returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if !result.Active {
		return ErrTokenInactive
	}
	return nil
}

// GetUserInfo retrieves the UserInfo (including DEZI declaration).
func (c *Client) GetUserInfo(accessToken string) (*models.DeziClaims, error) {
	if c.oidcMetadata == nil {
		return nil, ErrMetadataNotLoaded
	}
	if c.oidcMetadata.UserInfoEndpoint == "" {
		return nil, ErrUserInfoNotAvailable
	}

	req, err := http.NewRequest(http.MethodGet, c.oidcMetadata.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var claims models.DeziClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		if token, _ := jwt.ParseWithClaims(string(body), &claims, nil); token != nil {
			return &claims, nil
		}
		return nil, fmt.Errorf("parsing userinfo: %w", err)
	}

	return &claims, nil
}

// GetMetadata returns the OIDC metadata.
func (c *Client) GetMetadata() *models.OIDCConfig {
	return c.oidcMetadata
}

// ValidateTokenWithJWKS validates a JWT token using JWKS or embedded x5c certificate.
func (c *Client) ValidateTokenWithJWKS(ctx context.Context, tokenString string) (*models.AccessTokenClaims, error) {
	if c.oidcMetadata == nil {
		return nil, ErrMetadataNotLoaded
	}

	if ctx == nil {
		ctx = context.Background()
	}

	jwksSet := c.fetchJWKS(ctx)

	token, err := jwt.ParseWithClaims(tokenString, &models.AccessTokenClaims{}, func(token *jwt.Token) (any, error) {
		return c.getVerificationKey(token, jwksSet)
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*models.AccessTokenClaims)
	if !ok {
		return nil, errors.New("extracting claims from token")
	}

	if err := c.validateTokenClaims(claims); err != nil {
		return nil, err
	}

	c.logValidatedToken(claims)
	return claims, nil
}

// fetchJWKS fetches the JWKS from the configured endpoint.
func (c *Client) fetchJWKS(ctx context.Context) jwk.Set {
	if c.oidcMetadata.JWKSUri == "" {
		return nil
	}

	jwksSet, err := jwk.Fetch(ctx, c.oidcMetadata.JWKSUri)
	if err != nil {
		log.Printf("Warning: failed to fetch JWKS: %v", err)
		return nil
	}
	return jwksSet
}

// getVerificationKey extracts the verification key from token header.
func (c *Client) getVerificationKey(token *jwt.Token, jwksSet jwk.Set) (any, error) {
	if key, err := c.extractX5CKey(token); err == nil {
		return key, nil
	}

	if kid, ok := token.Header["kid"].(string); ok && jwksSet != nil {
		key, found := jwksSet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
		}

		var pubKey any
		if err := key.Raw(&pubKey); err != nil {
			return nil, fmt.Errorf("extracting public key: %w", err)
		}
		return pubKey, nil
	}

	return nil, ErrMissingKeyInfo
}

// extractX5CKey extracts the public key from x5c header.
func (c *Client) extractX5CKey(token *jwt.Token) (any, error) {
	x5cRaw, ok := token.Header["x5c"]
	if !ok {
		return nil, errors.New("x5c not present")
	}

	x5cArray, ok := x5cRaw.([]any)
	if !ok || len(x5cArray) == 0 {
		return nil, errors.New("x5c header is invalid or empty")
	}

	certStr, ok := x5cArray[0].(string)
	if !ok {
		return nil, errors.New("x5c certificate is not a string")
	}

	certBytes, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("decoding x5c certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing x5c certificate: %w", err)
	}

	log.Printf("Using x5c certificate: Subject=%s, Issuer=%s", cert.Subject, cert.Issuer)
	return cert.PublicKey, nil
}

// validateTokenClaims validates the standard JWT claims.
func (c *Client) validateTokenClaims(claims *models.AccessTokenClaims) error {
	expiresAt, err := claims.RegisteredClaims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("getting expiration time: %w", err)
	}
	if expiresAt != nil && expiresAt.Time.Before(time.Now()) {
		return ErrTokenExpired
	}
	return nil
}

func (c *Client) logValidatedToken(claims *models.AccessTokenClaims) {
	log.Printf("Token validated successfully:")
	log.Printf("  Issuer: %s", claims.Issuer)
	log.Printf("  Subject: %s", claims.Subject)
	log.Printf("  Audience: %v", claims.Audience)
	log.Printf("  TID: %s", claims.TID)
	log.Printf("  Subject Name: %s", claims.Extensions.IHEIUA.SubjectName)
	log.Printf("  Subject Organization: %s", claims.Extensions.IHEIUA.SubjectOrganization)
	log.Printf("  Person ID: %s", claims.Extensions.IHEIUA.PersonID)
}

// ValidateToken validates a JWT token using JWKS (convenience wrapper).
func (c *Client) ValidateToken(tokenString string) (*models.DeziClaims, error) {
	claims, err := c.ValidateTokenWithJWKS(context.Background(), tokenString)
	if err != nil {
		return nil, err
	}

	// Convert AccessTokenClaims to DeziClaims for the IDP service
	return &models.DeziClaims{
		Subject:          claims.Subject,
		Issuer:           claims.Issuer,
		Audience:         claims.Audience,
		BIGNumber:        claims.Extensions.IHEIUA.PersonID,
		BIGRoleCode:      claims.Extensions.IHEIUA.BIGRoleCode,
		URA:              claims.TID,
		OrganizationName: claims.Extensions.IHEIUA.SubjectOrganization,
		GivenName:        claims.Extensions.IHEIUA.SubjectName,
		FamilyName:       "",
		ExpiresAt:        claims.RegisteredClaims.ExpiresAt.Unix(),
	}, nil
}
