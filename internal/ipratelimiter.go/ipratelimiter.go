package ipratelimiter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
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
	Day       int // Day of month (1-31)
	Month     int // Month (1-12)
	Year      int // Year (e.g., 2025)
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
	limiter := &IPEndpointLimiter{
		limitsPerIP:      make(map[string]map[string][]Request),
		endpointSettings: make(map[string]*EndpointLimit),
		defaultLimit: &EndpointLimit{
			Path:              "*",
			MaxRequestsPerDay: defaultMaxRequestsPerDay,
		},
		cleanup: time.NewTicker(1 * time.Hour), // Hourly cleanup for daily limits
	}

	return limiter
}

// Start runs the cleanup routine - periodically removes requests from previous days
func (rl *IPEndpointLimiter) Start(ctx context.Context, runner service.Runner) error {
	runner.Go(func() error {
		defer rl.Close()

		for range rl.cleanup.C {
			rl.mu.Lock()
			now := time.Now()
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)

			// Keep only the last 7 days of data for analysis purposes
			oldestToKeep := today.AddDate(0, 0, -7)

			// For each IP address
			for ip, endpoints := range rl.limitsPerIP {
				endpointsToRemove := []string{}

				// For each endpoint this IP has accessed
				for endpoint, requests := range endpoints {
					var recentRequests []Request

					// Keep only recent requests
					for _, req := range requests {
						requestTime := time.Date(req.Year, time.Month(req.Month), req.Day, 0, 0, 0, 0, time.UTC)
						if requestTime.After(oldestToKeep) || requestTime.Equal(oldestToKeep) {
							recentRequests = append(recentRequests, req)
						}
					}

					// Update or mark for removal
					if len(recentRequests) > 0 {
						endpoints[endpoint] = recentRequests
					} else {
						endpointsToRemove = append(endpointsToRemove, endpoint)
					}
				}

				// Remove empty endpoints
				for _, endpoint := range endpointsToRemove {
					delete(endpoints, endpoint)
				}

				// Remove IP if no endpoints left
				if len(endpoints) == 0 {
					delete(rl.limitsPerIP, ip)
				}
			}
			rl.mu.Unlock()
		}
		return nil
	})
	return nil
}

// SetLimit adds or updates a rate limit for a specific endpoint
func (rl *IPEndpointLimiter) SetLimit(path string, maxRequestsPerDay int) {
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
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UTC()
	currentDay := now.Day()
	currentMonth := int(now.Month())
	currentYear := now.Year()

	// Get the limit for this endpoint
	limit := rl.defaultLimit
	if l, exists := rl.endpointSettings[endpoint]; exists {
		limit = l
	}

	// Initialize IP map if not exists
	if _, exists := rl.limitsPerIP[ip]; !exists {
		rl.limitsPerIP[ip] = make(map[string][]Request)
	}

	//TODO: need to check if we have to calculate all requests in the rate limit or manage them individualy

	// Initialize endpoint in IP map if not exists
	if _, exists := rl.limitsPerIP[ip][endpoint]; !exists {
		newRequest := Request{
			Timestamp: now,
			Day:       currentDay,
			Month:     currentMonth,
			Year:      currentYear,
		}
		rl.limitsPerIP[ip][endpoint] = []Request{newRequest}
		return true
	}

	// Count requests from the current day
	requests := rl.limitsPerIP[ip][endpoint]
	var todayRequests []Request
	for _, req := range requests {
		if req.Day == currentDay && req.Month == currentMonth && req.Year == currentYear {
			todayRequests = append(todayRequests, req)
		}
	}

	// Check if adding this request would exceed the limit
	if len(todayRequests) >= limit.MaxRequestsPerDay {
		// Record this request anyway for proper counting
		newRequest := Request{
			Timestamp: now,
			Day:       currentDay,
			Month:     currentMonth,
			Year:      currentYear,
		}
		rl.limitsPerIP[ip][endpoint] = append(requests, newRequest)
		return false
	}

	// Record and allow
	newRequest := Request{
		Timestamp: now,
		Day:       currentDay,
		Month:     currentMonth,
		Year:      currentYear,
	}
	rl.limitsPerIP[ip][endpoint] = append(requests, newRequest)
	return true
}

// GetCurrentUsage returns the number of requests made today
func (rl *IPEndpointLimiter) GetCurrentUsage(ip, endpoint string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	currentDay := now.Day()
	currentMonth := int(now.Month())
	currentYear := now.Year()

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
		if req.Day == currentDay && req.Month == currentMonth && req.Year == currentYear {
			count++
		}
	}

	return count
}

// GetRemainingTime returns the time until rate limit reset
func (rl *IPEndpointLimiter) GetRemainingTime() time.Duration {
	now := time.Now()
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.Local)
	return tomorrow.Sub(now)
}

// Close stops the cleanup ticker
func (rl *IPEndpointLimiter) Close() {
	rl.cleanup.Stop()
}

// RateLimitMiddleware applies rate limiting to routes
func (rl *IPEndpointLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get client IP
		ip := getClientIP(c)

		// Get endpoint path
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// Check if allowed
		if !rl.Allow(ip, path) {
			limit := rl.getEndpointLimit(path)
			usage := rl.GetCurrentUsage(ip, path)
			remaining := 0
			if limit.MaxRequestsPerDay > usage {
				remaining = limit.MaxRequestsPerDay - usage
			}

			// Get seconds until reset
			resetSeconds := int(rl.GetRemainingTime().Seconds())
			resetHours := int(rl.GetRemainingTime().Hours())
			resetMinutes := int(rl.GetRemainingTime().Minutes()) % 60

			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit.MaxRequestsPerDay))
			c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			c.Header("X-RateLimit-Used", fmt.Sprintf("%d", usage))
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()+int64(resetSeconds)))

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":    "Daily rate limit exceeded for this endpoint.",
				"limit":    limit.MaxRequestsPerDay,
				"used":     usage,
				"reset_in": fmt.Sprintf("%dh %dm", resetHours, resetMinutes),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(c *gin.Context) string {
	// Try X-Forwarded-For header first
	if xForwardedFor := c.Request.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// Try X-Real-IP header
	if xRealIP := c.Request.Header.Get("X-Real-IP"); xRealIP != "" {
		return strings.TrimSpace(xRealIP)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}

	return ip
}
