package ipratelimiter

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/service"
)

// EndpointLimit defines a rate limit for a specific endpoint
type EndpointLimit struct {
	Path              string
	MaxRequestsPerDay int
}

// Request stores information about an API request
type Request struct {
	Timestamp time.Time
}

// IPEndpointLimiter implements rate limiting per IP per endpoint on a daily basis
type IPEndpointLimiter struct {
	mu               sync.Mutex
	limitsPerIP      map[string]map[string][]Request // map[ip]map[endpoint][]requests
	endpointSettings map[string]*EndpointLimit       // map[endpoint]*EndpointLimit
	defaultLimit     *EndpointLimit
	cleanup          *time.Ticker
}

// NewIPEndpointLimiter creates a rate limiter with endpoint-specific daily limits
func NewIPEndpointLimiter(defaultMaxRequestsPerDay int) *IPEndpointLimiter {
	if defaultMaxRequestsPerDay < 0 {
		defaultMaxRequestsPerDay = 0
	}
	return &IPEndpointLimiter{
		limitsPerIP:      make(map[string]map[string][]Request),
		endpointSettings: make(map[string]*EndpointLimit),
		defaultLimit: &EndpointLimit{
			MaxRequestsPerDay: defaultMaxRequestsPerDay,
		},
		cleanup: time.NewTicker(1 * time.Hour),
	}
}

// cleanupExpiredData removes requests older than 1 day
func (rl *IPEndpointLimiter) cleanupExpiredData() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	oldestToKeep := today.AddDate(0, 0, -1)

	// For each IP address
	for ip, endpoints := range rl.limitsPerIP {
		endpointsToRemove := []string{}

		// For each endpoint this IP has accessed
		for endpoint, requests := range endpoints {
			var recentRequests []Request

			// Keep only recent requests
			for _, req := range requests {
				requestTime := req.Timestamp
				if requestTime.After(oldestToKeep) || requestTime.Equal(oldestToKeep) {
					recentRequests = append(recentRequests, req)
				}
			}

			// Update or mark for removal
			if len(recentRequests) > 0 {
				rl.limitsPerIP[ip][endpoint] = recentRequests
			} else {
				endpointsToRemove = append(endpointsToRemove, endpoint)
			}
		}

		// Remove empty endpoints
		for _, endpoint := range endpointsToRemove {
			delete(rl.limitsPerIP[ip], endpoint)
		}

		// Remove IP if no endpoints left
		if len(rl.limitsPerIP[ip]) == 0 {
			delete(rl.limitsPerIP, ip)
		}
	}
}

// Start runs the cleanup routine - periodically removes requests from previous days
func (rl *IPEndpointLimiter) Start(ctx context.Context, runner service.Runner) error {
	runner.Go(func() error {
		defer rl.Close()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-rl.cleanup.C:
				rl.cleanupExpiredData()
			}
		}
	})
	return nil
}

// SetLimit adds or updates a rate limit for a specific endpoint
func (rl *IPEndpointLimiter) SetLimit(path string, maxRequestsPerDay int) {
	if path == "" {
		return
	}
	if maxRequestsPerDay < 0 {
		maxRequestsPerDay = 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.endpointSettings[path] = &EndpointLimit{
		Path:              path,
		MaxRequestsPerDay: maxRequestsPerDay,
	}
}

// getEndpointLimit returns the limit settings for the given path
func (rl *IPEndpointLimiter) getEndpointLimit(path string) *EndpointLimit {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limit, exists := rl.endpointSettings[path]; exists {
		return limit
	}
	return rl.defaultLimit
}

// Allow checks if a request from the given IP to the given endpoint is allowed
func (rl *IPEndpointLimiter) Allow(ip, endpoint string) bool {
	if ip == "" || endpoint == "" {
		return false
	}

	// Validate IP address
	if net.ParseIP(ip) == nil {
		return false
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Get the limit for this endpoint
	limit := rl.defaultLimit
	if l, exists := rl.endpointSettings[endpoint]; exists {
		limit = l
	}

	// Initialize IP map if not exists
	if _, exists := rl.limitsPerIP[ip]; !exists {
		rl.limitsPerIP[ip] = make(map[string][]Request)
	}

	// Initialize endpoint in IP map if not exists
	if _, exists := rl.limitsPerIP[ip][endpoint]; !exists {
		rl.limitsPerIP[ip][endpoint] = []Request{}
	}

	// Count requests from the current day
	requests := rl.limitsPerIP[ip][endpoint]
	var todayRequests []Request
	for _, req := range requests {
		requestTime := time.Date(req.Timestamp.Year(), req.Timestamp.Month(), req.Timestamp.Day(), 0, 0, 0, 0, time.UTC)
		if requestTime.Equal(today) {
			todayRequests = append(todayRequests, req)
		}
	}

	// Check if adding this request would exceed the limit
	if len(todayRequests) >= limit.MaxRequestsPerDay {
		return false
	}

	// Record and allow
	newRequest := Request{
		Timestamp: now,
	}
	rl.limitsPerIP[ip][endpoint] = append(requests, newRequest)
	return true
}

// GetCurrentUsage returns the number of requests made today
func (rl *IPEndpointLimiter) GetCurrentUsage(ip, endpoint string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Check if IP exists
	endpoints, exists := rl.limitsPerIP[ip]
	if !exists {
		return 0
	}

	// Check if endpoint exists for this IP
	requests, exists := endpoints[endpoint]
	if !exists {
		return 0
	}

	// Count requests from today
	count := 0
	for _, req := range requests {
		requestTime := time.Date(req.Timestamp.Year(), req.Timestamp.Month(), req.Timestamp.Day(), 0, 0, 0, 0, time.UTC)
		if requestTime.Equal(today) {
			count++
		}
	}

	return count
}

// GetRemainingTime returns the time until rate limit reset
func (rl *IPEndpointLimiter) GetRemainingTime() time.Duration {
	now := time.Now().UTC()
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	return tomorrow.Sub(now)
}

// Close stops the cleanup ticker
func (rl *IPEndpointLimiter) Close() {
	rl.cleanup.Stop()
}

// RateLimitMiddleware applies rate limiting to routes
func (rl *IPEndpointLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil || c.Request == nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		ip := getClientIP(c)
		if ip == "" {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		endpoint := c.Request.URL.Path
		if !rl.Allow(ip, endpoint) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		c.Next()
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	// Get the remote address
	remoteAddr := c.Request.RemoteAddr
	if remoteAddr == "" {
		return ""
	}

	// Remove port if present
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if net.ParseIP(host) != nil {
			return host
		}
	} else {
		// Try parsing the whole string as an IP
		if net.ParseIP(remoteAddr) != nil {
			return remoteAddr
		}
	}

	return ""
}
