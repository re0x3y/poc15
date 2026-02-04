// Package httputil provides HTTP utility functions.
package httputil

import (
	"encoding/json"
	"net/http"
	"strings"
)

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// WriteJSONOK writes a JSON response with 200 OK status.
func WriteJSONOK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, data)
}

// WriteJSONNoCache writes a JSON response with no-cache headers.
func WriteJSONNoCache(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

// WriteBadRequest writes a 400 Bad Request error response.
func WriteBadRequest(w http.ResponseWriter, errorCode, description string) {
	WriteJSON(w, http.StatusBadRequest, map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// WriteUnauthorized writes a 401 Unauthorized error response.
func WriteUnauthorized(w http.ResponseWriter, errorCode, description string) {
	WriteJSON(w, http.StatusUnauthorized, map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// WriteInternalError writes a 500 Internal Server Error response.
func WriteInternalError(w http.ResponseWriter, errorCode, description string) {
	WriteJSON(w, http.StatusInternalServerError, map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// ExtractBearerToken extracts the bearer token from the Authorization header.
func ExtractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	return strings.TrimPrefix(auth, prefix), true
}
