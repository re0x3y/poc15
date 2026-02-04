// Package authz provides OAuth 2.0 authorization server functionality.
package authz

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/reoxey/poc15/internal/crypto"
	"github.com/reoxey/poc15/models"
)

// Default configuration values.
const (
	defaultAuthCodeTTL    = 10 * time.Minute
	defaultAccessTokenTTL = 1 * time.Hour
	tokenLength           = 32
)

// Common errors.
var (
	ErrInvalidAuthCode     = errors.New("invalid or expired authorization code")
	ErrInvalidAccessToken  = errors.New("invalid or expired access token")
	ErrInvalidCodeVerifier = errors.New("invalid PKCE code verifier")
	ErrClientMismatch      = errors.New("client_id mismatch")
	ErrRedirectMismatch    = errors.New("redirect_uri mismatch")
)

// Config holds the authorization server configuration.
type Config struct {
	Issuer         string
	AuthCodeTTL    time.Duration
	AccessTokenTTL time.Duration
}

// Server represents an OAuth 2.0 authorization server.
type Server struct {
	mu sync.RWMutex

	issuer         string
	authCodeTTL    time.Duration
	accessTokenTTL time.Duration

	authCodes    map[string]*authCodeInfo
	accessTokens map[string]*accessTokenInfo
}

type authCodeInfo struct {
	clientID      string
	redirectURI   string
	scope         string
	subject       string
	codeChallenge string
	expiresAt     time.Time
}

type accessTokenInfo struct {
	subject   string
	scope     string
	expiresAt time.Time
}

// Authorization represents an authorization response.
type Authorization struct {
	Code        string
	RedirectURI string
	State       string
}

// NewServer creates a new authorization server.
func NewServer(cfg *Config) *Server {
	authCodeTTL := cfg.AuthCodeTTL
	if authCodeTTL == 0 {
		authCodeTTL = defaultAuthCodeTTL
	}

	accessTokenTTL := cfg.AccessTokenTTL
	if accessTokenTTL == 0 {
		accessTokenTTL = defaultAccessTokenTTL
	}

	return &Server{
		issuer:         cfg.Issuer,
		authCodeTTL:    authCodeTTL,
		accessTokenTTL: accessTokenTTL,
		authCodes:      make(map[string]*authCodeInfo),
		accessTokens:   make(map[string]*accessTokenInfo),
	}
}

// CreateAuthorization creates an authorization code (ITI-71).
func (s *Server) CreateAuthorization(clientID, redirectURI, scope, subject, codeChallenge string) (*Authorization, error) {
	code, err := crypto.GenerateURLSafeToken(tokenLength)
	if err != nil {
		return nil, fmt.Errorf("generating auth code: %w", err)
	}

	s.mu.Lock()
	s.authCodes[code] = &authCodeInfo{
		clientID:      clientID,
		redirectURI:   redirectURI,
		scope:         scope,
		subject:       subject,
		codeChallenge: codeChallenge,
		expiresAt:     time.Now().Add(s.authCodeTTL),
	}
	s.mu.Unlock()

	return &Authorization{
		Code:        code,
		RedirectURI: redirectURI,
	}, nil
}

// ExchangeAuthorizationCode exchanges an auth code for tokens (ITI-71).
func (s *Server) ExchangeAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*models.TokenResponse, error) {
	s.mu.Lock()
	info, exists := s.authCodes[code]
	if exists {
		delete(s.authCodes, code)
	}
	s.mu.Unlock()

	if !exists || time.Now().After(info.expiresAt) {
		return nil, ErrInvalidAuthCode
	}

	if info.clientID != clientID {
		return nil, ErrClientMismatch
	}
	if info.redirectURI != redirectURI {
		return nil, ErrRedirectMismatch
	}

	if info.codeChallenge != "" {
		hash := sha256.Sum256([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if challenge != info.codeChallenge {
			return nil, ErrInvalidCodeVerifier
		}
	}

	accessToken, err := crypto.GenerateURLSafeToken(tokenLength)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	s.mu.Lock()
	s.accessTokens[accessToken] = &accessTokenInfo{
		subject:   info.subject,
		scope:     info.scope,
		expiresAt: time.Now().Add(s.accessTokenTTL),
	}
	s.mu.Unlock()

	return &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       info.scope,
	}, nil
}

// IntrospectToken introspects a token (ITI-102).
func (s *Server) IntrospectToken(token string) (map[string]any, error) {
	s.mu.RLock()
	info, exists := s.accessTokens[token]
	s.mu.RUnlock()

	if !exists || time.Now().After(info.expiresAt) {
		return map[string]any{"active": false}, nil
	}

	return map[string]any{
		"active":     true,
		"sub":        info.subject,
		"scope":      info.scope,
		"exp":        info.expiresAt.Unix(),
		"token_type": "Bearer",
	}, nil
}

// PerformAuthorizationDecision performs an authorization decision (ITI-102).
func (s *Server) PerformAuthorizationDecision(token, resourceType, action string) (*models.AuthorizationDecision, error) {
	s.mu.RLock()
	info, exists := s.accessTokens[token]
	s.mu.RUnlock()

	if !exists || time.Now().After(info.expiresAt) {
		return &models.AuthorizationDecision{
			Decision: models.DecisionDeny,
			Resource: resourceType,
			Action:   action,
		}, ErrInvalidAccessToken
	}

	return &models.AuthorizationDecision{
		Decision: models.DecisionPermit,
		Resource: resourceType,
		Action:   action,
		Subject:  info.subject,
	}, nil
}
