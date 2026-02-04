package httputil

import (
	"log"
	"net/http"
	"time"
)

// LoggingTransport is an http.RoundTripper that logs requests.
type LoggingTransport struct {
	Transport http.RoundTripper
	Enabled   bool
}

// RoundTrip implements http.RoundTripper.
func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Enabled {
		log.Printf("[%s %s]", req.Method, req.URL.String())
	}
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}

// NewLoggingClient creates an HTTP client with optional request logging.
func NewLoggingClient(timeout time.Duration, logRequests bool) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &LoggingTransport{
			Transport: http.DefaultTransport,
			Enabled:   logRequests,
		},
	}
}

// LoggingMiddleware wraps an http.Handler with request logging.
func LoggingMiddleware(next http.Handler, enabled bool) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s %s]", r.Method, r.URL.String())
		next.ServeHTTP(w, r)
	})
}
