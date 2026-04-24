package usecase

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
)

// Test to verify that QueryExternalKeyper correctly trims quotes and newlines from the response body.
func TestGetDecryptionKeyFromExternalKeyper_QuotedBody(t *testing.T) {
	expectedKey := "0xdeadbeefcaffee"

	// Setup mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusOK)

		// this is how rolling-shutter http-api encodes the result
		json.NewEncoder(w).Encode(expectedKey)
	}))
	defer server.Close()

	parsedURL, _ := url.Parse(server.URL)

	// Execute the function
	ctx := context.Background()
	result, err := QueryExternalKeyper(ctx, 1, "identity", parsedURL)

	assert.NilError(t, err, "QueryExternalKeyper errored", err)
	assert.Equal(t, result, expectedKey, "result not equal %v vs %v", result, expectedKey)
}
