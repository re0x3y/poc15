// Package dicomweb provides DICOMweb client and server implementations.
package dicomweb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/reoxey/poc15/models"
)

// TokenResponse represents OAuth 2.0 token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Client represents a DICOMweb client.
// Implements WADO-RS (Web Access to DICOM Objects) and QIDO-RS (Query based on ID for DICOM Objects).
type Client struct {
	mu         sync.RWMutex
	baseURL    string
	httpClient *http.Client

	// Authorization - IDP token exchange function
	getAuthToken func(targetResource string) (string, error)

	// Bearer token caching
	bearerToken       string
	bearerTokenExpiry time.Time
}

// NewClient creates a new DICOMweb client.
func NewClient(baseURL string, getAuthToken func(resource string) (string, error)) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		getAuthToken: getAuthToken,
	}
}

// getBearerToken gets or refreshes the DICOMweb bearer token.
func (c *Client) getBearerToken() (string, error) {
	c.mu.RLock()
	// Check if we have a valid cached bearer token
	if c.bearerToken != "" && time.Now().Before(c.bearerTokenExpiry) {
		token := c.bearerToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	// Need to get a new bearer token
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.bearerToken != "" && time.Now().Before(c.bearerTokenExpiry) {
		return c.bearerToken, nil
	}

	// Step 1: Get auth-token (assertion) from IDP
	authToken, err := c.getAuthToken(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("failed to get auth-token from IDP: %w", err)
	}

	// Step 2: Exchange auth-token for DICOMweb bearer token using JWT Bearer Grant (RFC7523)
	tokenURL := fmt.Sprintf("%s/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", authToken)

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	// Cache the bearer token (expire 30 seconds early to avoid edge cases)
	c.bearerToken = tokenResp.AccessToken
	c.bearerTokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-30) * time.Second)

	return c.bearerToken, nil
}

// SearchStudies performs a QIDO-RS search for studies.
func (c *Client) SearchStudies(patientID string) ([]*models.ImagingStudy, error) {
	// Get bearer token for DICOMweb access
	bearerToken, err := c.getBearerToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get bearer token: %w", err)
	}

	// QIDO-RS search endpoint
	reqURL := fmt.Sprintf("%s/studies?PatientID=%s", c.baseURL, patientID)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header with bearer token
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/dicom+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var studies []*models.ImagingStudy
	if err := json.NewDecoder(resp.Body).Decode(&studies); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return studies, nil
}

// RetrieveStudy retrieves a complete study via WADO-RS.
func (c *Client) RetrieveStudy(studyInstanceUID string) ([]byte, error) {
	bearerToken, err := c.getBearerToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get bearer token: %w", err)
	}

	reqURL := fmt.Sprintf("%s/studies/%s", c.baseURL, studyInstanceUID)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "multipart/related; type=\"application/dicom\"")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return data, nil
}

// RetrieveMetadata retrieves study metadata (without pixel data) via WADO-RS.
func (c *Client) RetrieveMetadata(studyInstanceUID string) (*models.ImagingStudy, error) {
	bearerToken, err := c.getBearerToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get bearer token: %w", err)
	}

	reqURL := fmt.Sprintf("%s/studies/%s/metadata", c.baseURL, studyInstanceUID)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/dicom+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var study models.ImagingStudy
	if err := json.NewDecoder(resp.Body).Decode(&study); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &study, nil
}
