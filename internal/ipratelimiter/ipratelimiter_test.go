package ipratelimiter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewIPEndpointLimiter(t *testing.T) {
	defaultLimit := 100
	limiter := NewIPEndpointLimiter(defaultLimit)

	assert.NotNil(t, limiter)
	assert.Equal(t, defaultLimit, limiter.defaultLimit.MaxRequestsPerDay)
	assert.NotNil(t, limiter.limitsPerIP)
	assert.NotNil(t, limiter.endpointSettings)
	assert.NotNil(t, limiter.cleanup)
}

func TestSetLimit(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)
	path := "/test"
	maxRequests := 50

	limiter.SetLimit(path, maxRequests)

	limit := limiter.getEndpointLimit(path)
	assert.Equal(t, maxRequests, limit.MaxRequestsPerDay)
	assert.Equal(t, path, limit.Path)
}

func TestAllow(t *testing.T) {
	limiter := NewIPEndpointLimiter(2) // Set a small limit for testing
	ip := "127.0.0.1"
	endpoint := "/test"

	// First request should be allowed
	assert.True(t, limiter.Allow(ip, endpoint))
	assert.Equal(t, 1, limiter.GetCurrentUsage(ip, endpoint))

	// Second request should be allowed
	assert.True(t, limiter.Allow(ip, endpoint))
	assert.Equal(t, 2, limiter.GetCurrentUsage(ip, endpoint))

	// Third request should be denied
	assert.False(t, limiter.Allow(ip, endpoint))
	assert.Equal(t, 2, limiter.GetCurrentUsage(ip, endpoint))
}

func TestGetCurrentUsage(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)
	ip := "127.0.0.1"
	endpoint := "/test"

	// Initial usage should be 0
	assert.Equal(t, 0, limiter.GetCurrentUsage(ip, endpoint))

	// Make a request and check usage
	limiter.Allow(ip, endpoint)
	assert.Equal(t, 1, limiter.GetCurrentUsage(ip, endpoint))

	// Make another request and check usage
	limiter.Allow(ip, endpoint)
	assert.Equal(t, 2, limiter.GetCurrentUsage(ip, endpoint))
}

func TestGetRemainingTime(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)
	remainingTime := limiter.GetRemainingTime()

	// Remaining time should be less than 24 hours
	assert.True(t, remainingTime < 24*time.Hour)
	// Remaining time should be positive
	assert.True(t, remainingTime > 0)
}

func TestRateLimitMiddleware(t *testing.T) {
	limiter := NewIPEndpointLimiter(2) // Set a small limit for testing
	router := gin.New()
	router.Use(limiter.RateLimitMiddleware())

	// Setup test endpoint
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// First request should succeed
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234" // Set RemoteAddr for the request
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should succeed
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234" // Set RemoteAddr for the request
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Third request should be rate limited
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:1234" // Set RemoteAddr for the request
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Test with different IP should succeed
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.2:1234" // Different IP
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test with invalid IP should fail
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "invalid-ip" // Invalid IP
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetClientIP(t *testing.T) {
	// Test valid RemoteAddr with port
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "192.168.1.1:1234"
	assert.Equal(t, "192.168.1.1", getClientIP(c))

	// Test valid RemoteAddr without port
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "192.168.1.2"
	assert.Equal(t, "192.168.1.2", getClientIP(c))

	// Test nil context
	assert.Equal(t, "", getClientIP(nil))

	// Test nil request
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	assert.Equal(t, "", getClientIP(c))
}

func TestGetClientIPWithInvalidHeaders(t *testing.T) {
	// Test with empty RemoteAddr
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = ""
	assert.Equal(t, "", getClientIP(c))

	// Test with invalid RemoteAddr format
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "invalid-address"
	assert.Equal(t, "", getClientIP(c))

	// Test with invalid IP in RemoteAddr
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/", nil)
	c.Request.RemoteAddr = "256.256.256.256:1234"
	assert.Equal(t, "", getClientIP(c))
}

func TestInvalidIPAddress(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)
	endpoint := "/test"

	// Test with empty IP
	assert.False(t, limiter.Allow("", endpoint))
	assert.Equal(t, 0, limiter.GetCurrentUsage("", endpoint))

	// Test with invalid IP format
	assert.False(t, limiter.Allow("invalid.ip.address", endpoint))
	assert.Equal(t, 0, limiter.GetCurrentUsage("invalid.ip.address", endpoint))
}

func TestInvalidEndpoint(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)
	ip := "127.0.0.1"

	// Test with empty endpoint
	assert.False(t, limiter.Allow(ip, ""))
	assert.Equal(t, 0, limiter.GetCurrentUsage(ip, ""))

	// Test with non-existent endpoint (should use default limit)
	assert.True(t, limiter.Allow(ip, "/nonexistent"))
	assert.Equal(t, 1, limiter.GetCurrentUsage(ip, "/nonexistent"))

	// Test with non-existent endpoint after reaching limit
	// Set a very low limit for testing
	limiter = NewIPEndpointLimiter(1)
	assert.True(t, limiter.Allow(ip, "/nonexistent"))
	assert.False(t, limiter.Allow(ip, "/nonexistent"))
	assert.Equal(t, 1, limiter.GetCurrentUsage(ip, "/nonexistent"))
}

func TestNegativeLimit(t *testing.T) {
	// Test with negative default limit
	limiter := NewIPEndpointLimiter(-1)
	assert.Equal(t, 0, limiter.defaultLimit.MaxRequestsPerDay)

	// Test setting negative limit for endpoint
	limiter.SetLimit("/test", -1)
	limit := limiter.getEndpointLimit("/test")
	assert.Equal(t, 0, limit.MaxRequestsPerDay)
}

func TestConcurrentAccess(t *testing.T) {
	limiter := NewIPEndpointLimiter(1000)
	ip := "127.0.0.1"
	endpoint := "/test"
	concurrentRequests := 100

	// Channel to collect results
	results := make(chan bool, concurrentRequests)

	// Launch concurrent requests
	for i := 0; i < concurrentRequests; i++ {
		go func() {
			results <- limiter.Allow(ip, endpoint)
		}()
	}

	// Collect results
	allowedCount := 0
	for i := 0; i < concurrentRequests; i++ {
		if <-results {
			allowedCount++
		}
	}

	// Verify we didn't exceed the limit
	assert.True(t, allowedCount <= 1000, "Concurrent requests exceeded limit")
	assert.Equal(t, allowedCount, limiter.GetCurrentUsage(ip, endpoint))
}

func TestCleanupWithExpiredData(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)

	// Add some test data with old timestamps
	ip := "127.0.0.1"
	endpoint := "/test"

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Create a request from 24 hours ago
	oldTime := today.AddDate(0, 0, -1).Add(-1 * time.Second)
	oldRequest := Request{
		Timestamp: oldTime,
	}

	// Add the old request to the limiter
	limiter.mu.Lock()
	if _, exists := limiter.limitsPerIP[ip]; !exists {
		limiter.limitsPerIP[ip] = make(map[string][]Request)
	}
	limiter.limitsPerIP[ip][endpoint] = []Request{oldRequest}
	limiter.mu.Unlock()

	// Run cleanup directly
	limiter.cleanupExpiredData()

	// Verify old data was cleaned up
	limiter.mu.Lock()
	requests, exists := limiter.limitsPerIP[ip][endpoint]
	limiter.mu.Unlock()

	if exists {
		assert.Equal(t, 0, len(requests), "Old data should have been cleaned up")
	}

	// Add a recent request and verify it's not cleaned up
	recentTime := time.Now().UTC()
	recentRequest := Request{
		Timestamp: recentTime,
	}

	limiter.mu.Lock()
	if _, exists := limiter.limitsPerIP[ip]; !exists {
		limiter.limitsPerIP[ip] = make(map[string][]Request)
	}
	limiter.limitsPerIP[ip][endpoint] = []Request{recentRequest}
	limiter.mu.Unlock()

	// Run cleanup again
	limiter.cleanupExpiredData()

	// Verify recent data is still there
	limiter.mu.Lock()
	requests, exists = limiter.limitsPerIP[ip][endpoint]
	limiter.mu.Unlock()

	assert.True(t, exists, "Recent data should not be cleaned up")
	assert.Equal(t, 1, len(requests), "Recent data should not be cleaned up")

	limiter.Close()
}

func TestMiddlewareWithInvalidContext(t *testing.T) {
	limiter := NewIPEndpointLimiter(100)
	router := gin.New()
	router.Use(limiter.RateLimitMiddleware())

	// Test with nil context
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDifferentEndpointLimits(t *testing.T) {
	limiter := NewIPEndpointLimiter(100) // Default limit
	ip := "127.0.0.1"

	// Set up two endpoints with different limits
	endpoint1 := "/endpoint1"
	endpoint2 := "/endpoint2"
	limiter.SetLimit(endpoint1, 2) // Small limit
	limiter.SetLimit(endpoint2, 5) // Larger limit

	// Test endpoint1 with small limit
	assert.True(t, limiter.Allow(ip, endpoint1))  // First request
	assert.True(t, limiter.Allow(ip, endpoint1))  // Second request
	assert.False(t, limiter.Allow(ip, endpoint1)) // Should be blocked
	assert.Equal(t, 2, limiter.GetCurrentUsage(ip, endpoint1))

	// Test endpoint2 with larger limit
	assert.True(t, limiter.Allow(ip, endpoint2))  // First request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Second request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Third request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Fourth request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Fifth request
	assert.False(t, limiter.Allow(ip, endpoint2)) // Should be blocked
	assert.Equal(t, 5, limiter.GetCurrentUsage(ip, endpoint2))
}

func TestEndpointLimitsIndependent(t *testing.T) {
	limiter := NewIPEndpointLimiter(100) // Default limit
	ip := "127.0.0.1"

	// Set up two endpoints with different limits
	endpoint1 := "/endpoint1"
	endpoint2 := "/endpoint2"
	limiter.SetLimit(endpoint1, 2) // Small limit
	limiter.SetLimit(endpoint2, 5) // Larger limit

	// Max out the larger limit endpoint first
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(ip, endpoint2))
	}
	assert.False(t, limiter.Allow(ip, endpoint2)) // Should be blocked
	assert.Equal(t, 5, limiter.GetCurrentUsage(ip, endpoint2))

	// Verify smaller limit endpoint is still accessible
	assert.True(t, limiter.Allow(ip, endpoint1))  // First request
	assert.True(t, limiter.Allow(ip, endpoint1))  // Second request
	assert.False(t, limiter.Allow(ip, endpoint1)) // Should be blocked
	assert.Equal(t, 2, limiter.GetCurrentUsage(ip, endpoint1))

	// Now max out the smaller limit endpoint
	// Reset the test by creating a new limiter
	limiter = NewIPEndpointLimiter(100)
	limiter.SetLimit(endpoint1, 2)
	limiter.SetLimit(endpoint2, 5)

	// Max out the smaller limit endpoint
	assert.True(t, limiter.Allow(ip, endpoint1))  // First request
	assert.True(t, limiter.Allow(ip, endpoint1))  // Second request
	assert.False(t, limiter.Allow(ip, endpoint1)) // Should be blocked
	assert.Equal(t, 2, limiter.GetCurrentUsage(ip, endpoint1))

	// Verify larger limit endpoint is still accessible
	assert.True(t, limiter.Allow(ip, endpoint2))  // First request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Second request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Third request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Fourth request
	assert.True(t, limiter.Allow(ip, endpoint2))  // Fifth request
	assert.False(t, limiter.Allow(ip, endpoint2)) // Should be blocked
	assert.Equal(t, 5, limiter.GetCurrentUsage(ip, endpoint2))
}
