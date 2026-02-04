// Package config provides configuration management for POC 15.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AppConfig holds the complete application configuration.
type AppConfig struct {
	Server   ServerConfig   `yaml:"server"`
	IDP      IDPConfig      `yaml:"idp"`
	Authz    AuthzConfig    `yaml:"authz"`
	Dezi     DeziConfig     `yaml:"dezi"`
	DICOMweb DICOMwebConfig `yaml:"dicomweb"`
	IHEIUA   IHEIUAConfig   `yaml:"ihe_iua"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	PACSAddr          string        `yaml:"pacs_addr"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
}

// IDPConfig holds Identity Provider configuration.
type IDPConfig struct {
	Issuer         string        `yaml:"issuer"`
	AuthTokenTTL   time.Duration `yaml:"auth_token_ttl"`
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`
}

// AuthzConfig holds Authorization server configuration.
type AuthzConfig struct {
	Issuer         string        `yaml:"issuer"`
	AuthCodeTTL    time.Duration `yaml:"auth_code_ttl"`
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`
}

// DeziConfig holds DEZI OIDC client configuration.
type DeziConfig struct {
	Issuer                string        `yaml:"issuer"`
	ClientID              string        `yaml:"client_id"`
	ClientSecret          string        `yaml:"client_secret"`
	RedirectURI           string        `yaml:"redirect_uri"`
	Scopes                []string      `yaml:"scopes"`
	TokenExchangeResource string        `yaml:"token_exchange_resource"`
	IntrospectURL         string        `yaml:"introspect_url"`
	HTTPTimeout           time.Duration `yaml:"http_timeout"`
}

// DICOMwebConfig holds DICOMweb server configuration.
type DICOMwebConfig struct {
	BaseURL           string        `yaml:"base_url"`
	BearerTokenTTL    time.Duration `yaml:"bearer_token_ttl"`
	BearerTokenSecret string        `yaml:"bearer_token_secret"`
	CleanupInterval   time.Duration `yaml:"cleanup_interval"`
}

// IHEIUAConfig holds IHE IUA token exchange configuration.
type IHEIUAConfig struct {
	TID          string           `yaml:"tid"`
	PersonID     string           `yaml:"person_id"`
	PurposeOfUse PurposeOfUseCode `yaml:"purpose_of_use"`
}

// PurposeOfUseCode represents the purpose of use coding.
type PurposeOfUseCode struct {
	System string `yaml:"system"`
	Code   string `yaml:"code"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	HTTPRequests bool   `yaml:"http_requests"`
	Level        string `yaml:"level"`
}

// Load reads configuration from a YAML file.
func Load(path string) (*AppConfig, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{
			PACSAddr:          ":8083",
			ReadHeaderTimeout: 10 * time.Second,
		},
		Authz: AuthzConfig{
			Issuer:         "http://localhost:8082",
			AuthCodeTTL:    10 * time.Minute,
			AccessTokenTTL: 1 * time.Hour,
		},
		DICOMweb: DICOMwebConfig{
			BaseURL:           "http://localhost:8083",
			BearerTokenTTL:    1 * time.Hour,
			BearerTokenSecret: "dicomweb-secret-key-change-in-production",
			CleanupInterval:   5 * time.Minute,
		},
		Logging: LoggingConfig{
			HTTPRequests: true,
			Level:        "info",
		},
	}
}
