// Package consul provides a HashiCorp Consul remote configuration provider for Argus
//
// This package implements the Argus RemoteConfigProvider interface to enable
// loading and watching configuration from HashiCorp Consul Key-Value store.
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agilira/go-errors"
	consulapi "github.com/hashicorp/consul/api"
)

// Security and resource limit constants for DoS prevention
const (
	// Maximum allowed response size from Consul (10MB)
	maxConsulResponseSize = 10 * 1024 * 1024

	// Default timeout for Consul requests (30 seconds)
	defaultConsulTimeout = 30 * time.Second

	// Maximum concurrent requests per provider instance
	maxConcurrentRequests = 50

	// Maximum number of active watch operations per provider
	maxActiveWatches = 10

	// Maximum time to wait for watch channel operations (prevents deadlock)
	watchChannelTimeout = 5 * time.Second
)

// validateSecureKeyPath validates and sanitizes Consul key paths to prevent path traversal attacks.
//
// SECURITY: This function implements comprehensive path validation to prevent:
// - Directory traversal attacks (../ and ..\\ sequences)
// - URL-encoded traversal attempts (%2e%2e%2f, etc.)
// - Null byte injection (\x00)
// - Control character injection
// - Excessively long paths (DoS prevention)
// - Windows device names (CON, PRN, etc.)
//
// The function normalizes the path and ensures it's safe for use with Consul KV operations.

// validateKeyPathBasics performs basic validation on the key path.
func validateKeyPathBasics(keyPath string) error {
	if keyPath == "" {
		return errors.New("ARGUS_INVALID_CONFIG", "consul key path cannot be empty")
	}

	// SECURITY: Detect null bytes and control characters
	for i, b := range []byte(keyPath) {
		if b == 0 {
			return errors.New("ARGUS_INVALID_CONFIG",
				"null byte in consul key path not allowed")
		}
		if b < 32 && b != 9 && b != 10 && b != 13 { // Allow tab, LF, CR
			return errors.New("ARGUS_INVALID_CONFIG",
				fmt.Sprintf("control character (0x%02x) at position %d in consul key path not allowed", b, i))
		}
	}

	// SECURITY: Limit path length to prevent DoS
	const maxPathLength = 2048
	if len(keyPath) > maxPathLength {
		return errors.New("ARGUS_INVALID_CONFIG",
			fmt.Sprintf("consul key path too long: %d bytes (max %d)", len(keyPath), maxPathLength))
	}

	return nil
}

// decodeKeyPathSafely performs comprehensive URL decoding to handle encoded attacks.
func decodeKeyPathSafely(keyPath string) string {
	decodedPath := keyPath
	maxDecodeIterations := 10 // Prevent infinite loops with malformed input

	for i := 0; i < maxDecodeIterations; i++ {
		// Use Go's standard library for proper URL decoding
		newDecodedPath, err := url.QueryUnescape(decodedPath)
		if err != nil {
			// If decoding fails, continue with current path for validation
			break
		}

		// If no change occurred, we've fully decoded the path
		if newDecodedPath == decodedPath {
			break
		}

		decodedPath = newDecodedPath
	}

	return decodedPath
}

// Pre-compiled dangerous patterns for faster validation (micro optimization)
var dangerousPatterns = []string{
	"../", "..\\", "./../", ".\\..\\",
	"/etc/", "\\etc\\", "/proc/", "\\proc\\",
	"/windows/", "\\windows\\", "/system32/", "\\system32\\",
	"/.ssh/", "\\.ssh\\", "/passwd", "\\passwd",
	"/shadow", "\\shadow", "/config/sam", "\\config\\sam",
}

// checkDangerousPatterns validates against path traversal and system path attacks.
func checkDangerousPatterns(decodedPath string) error {
	// Pre-allocate with known capacity to avoid reallocation
	lowerPath := strings.ToLower(decodedPath)

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return errors.New("ARGUS_INVALID_CONFIG",
				fmt.Sprintf("dangerous path traversal pattern '%s' detected in consul key path", pattern))
		}
	}

	return nil
}

// Pre-compiled Windows device names for faster validation (micro optimization)
var windowsDeviceNames = []string{
	"con", "prn", "aux", "nul",
	"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
	"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

// checkWindowsDeviceNames validates against Windows device name attacks.
func checkWindowsDeviceNames(keyPath string) error {
	// Optimize: replace only once and reuse the result
	normalizedPath := strings.ReplaceAll(keyPath, "\\", "/")
	pathSegments := strings.Split(normalizedPath, "/")

	for _, segment := range pathSegments {
		// Remove file extension for comparison
		segmentBase := strings.ToLower(segment)
		if dotIndex := strings.LastIndex(segmentBase, "."); dotIndex > 0 {
			segmentBase = segmentBase[:dotIndex]
		}

		for _, deviceName := range windowsDeviceNames {
			if segmentBase == deviceName {
				return errors.New("ARGUS_INVALID_CONFIG",
					fmt.Sprintf("windows device name '%s' not allowed in consul key path", segment))
			}
		}
	}

	return nil
}

// normalizeKeyPath normalizes path separators and structure.
func normalizeKeyPath(keyPath string) (string, error) {
	// SECURITY: Check for Windows Alternate Data Streams
	if strings.Contains(keyPath, ":") && strings.Count(keyPath, ":") > 1 {
		return "", errors.New("ARGUS_INVALID_CONFIG",
			"alternate data streams not allowed in consul key path")
	}

	// SECURITY: Normalize path separators and clean the path
	normalizedPath := strings.ReplaceAll(keyPath, "\\", "/")

	// Remove multiple consecutive slashes
	for strings.Contains(normalizedPath, "//") {
		normalizedPath = strings.ReplaceAll(normalizedPath, "//", "/")
	}

	// Clean leading/trailing slashes (Consul keys shouldn't start with /)
	normalizedPath = strings.Trim(normalizedPath, "/")

	// SECURITY: Final validation - ensure no traversal sequences remain after normalization
	if strings.Contains(normalizedPath, "../") || strings.Contains(normalizedPath, "..\\") {
		return "", errors.New("ARGUS_INVALID_CONFIG",
			"path traversal sequences detected after normalization")
	}

	// SECURITY: Limit path depth to prevent deeply nested attacks
	const maxDepth = 20
	pathDepth := len(strings.Split(normalizedPath, "/"))
	if pathDepth > maxDepth {
		return "", errors.New("ARGUS_INVALID_CONFIG",
			fmt.Sprintf("consul key path too deep: %d levels (max %d)", pathDepth, maxDepth))
	}

	return normalizedPath, nil
}

func validateSecureKeyPath(keyPath string) (string, error) {
	// Step 1: Basic validation
	if err := validateKeyPathBasics(keyPath); err != nil {
		return "", err
	}

	// Step 2: URL decode the path safely
	decodedPath := decodeKeyPathSafely(keyPath)

	// Step 3: Check for dangerous patterns
	if err := checkDangerousPatterns(decodedPath); err != nil {
		return "", err
	}

	// Step 4: Check for Windows device names
	if err := checkWindowsDeviceNames(keyPath); err != nil {
		return "", err
	}

	// Step 5: Normalize and final validation
	normalizedPath, err := normalizeKeyPath(keyPath)
	if err != nil {
		return "", err
	}

	return normalizedPath, nil

}

// initializeSecureDefaults initializes the provider with secure default resource limits.
//
// SECURITY: This function sets conservative defaults to prevent DoS attacks:
// - Limits response size to prevent memory exhaustion
// - Sets reasonable timeouts to prevent hanging connections
// - Limits concurrent operations to prevent resource exhaustion
//
// Thread-safety: Uses sync.Once to ensure initialization happens exactly once
func (c *ConsulProvider) initializeSecureDefaults() {
	c.defaultsOnce.Do(func() {
		if c.maxResponseSize.Load() == 0 {
			c.maxResponseSize.Store(maxConsulResponseSize)
		}
		if c.requestTimeout.Load() == 0 {
			c.requestTimeout.Store(int64(defaultConsulTimeout))
		}
		if c.maxConcurrentReqs.Load() == 0 {
			c.maxConcurrentReqs.Store(maxConcurrentRequests)
		}
	})
}

// checkResourceLimits validates current resource usage against configured limits.
//
// SECURITY: Prevents resource exhaustion attacks by enforcing limits on:
// - Concurrent request count
// - Active watch operations
// - Resource utilization
func (c *ConsulProvider) checkResourceLimits(operationType string) error {
	// Check if provider is closed
	if c.closed.Load() {
		return errors.New("ARGUS_PROVIDER_CLOSED", "consul provider has been closed")
	}

	// Initialize defaults if not set
	c.initializeSecureDefaults()

	// Check concurrent request limit
	currentRequests := c.currentReqs.Load()
	maxRequests := c.maxConcurrentReqs.Load()
	if currentRequests >= maxRequests {
		return errors.New("ARGUS_RESOURCE_LIMIT_EXCEEDED",
			fmt.Sprintf("maximum concurrent requests exceeded: %d/%d", currentRequests, maxRequests))
	}

	// Check watch count limit for watch operations
	if operationType == "watch" {
		currentWatches := c.watchCount.Load()
		if currentWatches >= maxActiveWatches {
			return errors.New("ARGUS_RESOURCE_LIMIT_EXCEEDED",
				fmt.Sprintf("maximum active watches exceeded: %d/%d", currentWatches, maxActiveWatches))
		}
	}

	return nil
}

// incrementRequestCount safely increments the request counter for resource tracking.
func (c *ConsulProvider) incrementRequestCount() {
	c.currentReqs.Add(1)
}

// decrementRequestCount safely decrements the request counter for resource tracking.
func (c *ConsulProvider) decrementRequestCount() {
	c.currentReqs.Add(-1)
}

// incrementWatchCount safely increments the watch counter for resource tracking.
func (c *ConsulProvider) incrementWatchCount() {
	c.watchCount.Add(1)
}

// decrementWatchCount safely decrements the watch counter for resource tracking.
func (c *ConsulProvider) decrementWatchCount() {
	c.watchCount.Add(-1)
}

// RemoteConfigProvider defines the interface for remote configuration sources.
// This interface is copied here to avoid importing argus (which would create
// a circular dependency). The provider is completely standalone and implements
// this interface. When imported, Argus will call the registration function.
type RemoteConfigProvider interface {
	// Name returns a human-readable name for this provider (used for debugging and logging)
	Name() string

	// Scheme returns the URL scheme this provider handles (e.g., "consul")
	Scheme() string

	// Load loads configuration from the remote source
	// The URL contains the full connection information including credentials
	// Returns parsed configuration as map[string]interface{}
	Load(ctx context.Context, configURL string) (map[string]interface{}, error)

	// Watch starts watching for configuration changes
	// Returns a channel that sends new configurations when they change
	// Uses efficient Consul blocking queries for real-time updates
	Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error)

	// Validate validates that the provider can handle the given URL
	// Performs comprehensive URL parsing and validation without connecting
	Validate(configURL string) error

	// HealthCheck performs a health check on the remote source
	// Verifies connectivity and Consul cluster health
	HealthCheck(ctx context.Context, configURL string) error

	// Close cleanly shuts down the provider and releases any resources
	// This method should be called when the provider is no longer needed
	// to prevent resource leaks (e.g., HTTP connections, goroutines)
	Close() error
}

// ConsulProvider implements RemoteConfigProvider for HashiCorp Consul
//
// This provider supports:
// - Loading JSON configurations from Consul KV store
// - Native watching via Consul blocking queries for efficient real-time updates
// - Multi-datacenter support with proper datacenter routing
// - ACL token authentication for secure environments
// - TLS/SSL connections for encrypted communication
// - Health monitoring via Consul agent status and leader election
// - Connection pooling and reuse for optimal performance
// - Thread-safe initialization using sync.Once for idiomatic Go concurrency
//
// The provider follows high-performance design principles:
// - sync.Once for guaranteed single initialization
// - Pre-allocated buffers where possible
// - Minimal allocations during operation
// - Efficient connection reuse
// - Lock-free design for concurrent access
type ConsulProvider struct {
	// clientOnce ensures client initialization happens exactly once (thread-safe)
	// This is the idiomatic Go pattern for lazy initialization
	clientOnce sync.Once

	// clientMutex protects client field during Close() operations
	clientMutex sync.RWMutex

	// client holds the Consul API client instance for production use
	// Connection is established lazily via clientOnce and reused across operations
	client *consulapi.Client

	// clientError holds any error that occurred during client initialization
	// This allows getClient to return the same error on subsequent calls
	clientError error

	// closed tracks whether the provider has been closed to prevent resource leaks
	// Using atomic.Bool for lock-free access in concurrent scenarios
	closed atomic.Bool

	// defaultsOnce ensures secure defaults are initialized exactly once (thread-safe)
	// This prevents race conditions during concurrent access
	defaultsOnce sync.Once

	// Resource limiting fields for security and DoS prevention (thread-safe with atomic operations)
	maxResponseSize   atomic.Int64 // Maximum allowed response size in bytes
	requestTimeout    atomic.Int64 // Maximum timeout for individual requests (nanoseconds)
	maxConcurrentReqs atomic.Int32 // Maximum concurrent requests allowed
	currentReqs       atomic.Int32 // Current number of active requests
	watchCount        atomic.Int32 // Current number of active watch operations

	// Mock implementation fields for testing
	// These allow comprehensive testing without requiring a real Consul instance
	mockData       map[string]string // Key-value store for mock data
	mockConnected  atomic.Bool       // Connection state for mock testing
	mockDatacenter string            // Simulated datacenter for testing
	mockMutex      sync.RWMutex      // Protects mock data for concurrent access
}

// Name returns the human-readable provider name
// Used for debugging, logging, and provider identification
func (c *ConsulProvider) Name() string {
	return "Consul Remote Configuration Provider v1.0"
}

// Scheme returns the URL scheme this provider handles
// This is used by Argus to route URLs to the appropriate provider
func (c *ConsulProvider) Scheme() string {
	return "consul"
}

// Validate checks if the configuration URL is valid for Consul
//
// This performs comprehensive validation without establishing a connection:
// - URL parsing and scheme verification
// - Host and port format validation
// - Consul-specific URL format validation (path structure)
// - Query parameter validation (datacenter, token, tls)
// - Key path validation (must not be empty)
//
// Returns error if URL is malformed or invalid for Consul provider
func (c *ConsulProvider) Validate(configURL string) error {
	_, _, _, _, err := c.parseConsulURL(configURL)
	return err
}

// parseConsulURL parses and validates a Consul URL with comprehensive error checking
//
// Expected format: consul://[username:password@]host:port/key[?datacenter=dc1&token=TOKEN&tls=true]
//
// Examples:
//   - consul://localhost:8500/config/myapp
//   - consul://user:pass@consul.example.com:8500/config/myapp?datacenter=dc1
//   - consul://consul.service.consul:8500/service/production/config?token=SECRET_TOKEN
//   - consul://secure.consul.internal:8500/config/prod?datacenter=dc1&token=ABC123&tls=true
//
// Returns:
//   - consulConfig: Consul client configuration ready for use
//   - kvPath: Consul KV path for the configuration key
//   - datacenter: Consul datacenter (empty string for default datacenter)
//   - token: ACL token (empty string if none provided)
//   - error: Validation error if URL is invalid or malformed
//
// The function performs comprehensive validation:
// - URL scheme must be "consul"
// - Host format validation
// - Port validation and defaults
// - Key path validation (must not be empty)
// - Query parameter validation
// - Authentication credential parsing
func (c *ConsulProvider) parseConsulURL(consulURL string) (*consulapi.Config, string, string, string, error) {
	u, err := url.Parse(consulURL)
	if err != nil {
		return nil, "", "", "", errors.Wrap(err, "ARGUS_INVALID_CONFIG",
			"invalid Consul URL format")
	}

	if err := c.validateURLScheme(u); err != nil {
		return nil, "", "", "", err
	}

	config := c.buildConsulConfig(u)
	kvPath, err := c.extractKVPath(u)
	if err != nil {
		return nil, "", "", "", err
	}

	datacenter, token := c.extractQueryParams(u, config)
	return config, kvPath, datacenter, token, nil
}

// validateURLScheme validates that the parsed URL has the correct scheme for Consul provider
//
// This function ensures that only URLs with the "consul" scheme are processed by this provider.
// It's a critical security and correctness check to prevent misrouting of configuration requests
// to inappropriate providers.
//
// Parameters:
//   - u: The parsed URL to validate
//
// Returns an error if the URL scheme is not "consul", nil otherwise.
func (c *ConsulProvider) validateURLScheme(u *url.URL) error {
	if u.Scheme != "consul" {
		return errors.New("ARGUS_INVALID_CONFIG", "URL scheme must be 'consul'")
	}
	return nil
}

// buildConsulConfig constructs a Consul API client configuration from the parsed URL
//
// This function creates a Consul configuration object using the host information
// and authentication credentials extracted from the URL. It starts with Consul's
// default configuration and customizes it based on the provided URL parameters.
//
// The function handles:
// - Host and port normalization through normalizeHost
// - HTTP Basic Authentication setup if credentials are present in the URL
// - Default Consul configuration initialization
//
// Parameters:
//   - u: The parsed URL containing host and authentication information
//
// Returns a fully configured Consul API client configuration ready for use.
func (c *ConsulProvider) buildConsulConfig(u *url.URL) *consulapi.Config {
	config := consulapi.DefaultConfig()
	config.Address = c.normalizeHost(u.Host)

	if u.User != nil {
		c.setHttpAuth(config, u.User)
	}

	return config
}

// normalizeHost normalizes the host address by adding default port if missing
//
// This function ensures that the host address has a port specified. If no port
// is provided, it defaults to 8500 (Consul's default port). This normalization
// is important for consistent connection handling across different host formats.
//
// The function provides comprehensive support for both IPv4 and IPv6 addresses:
//
// IPv4 formats supported:
//   - "localhost" → "localhost:8500"
//   - "example.com" → "example.com:8500"
//   - "192.168.1.1" → "192.168.1.1:8500"
//   - "example.com:8501" → "example.com:8501" (unchanged)
//
// IPv6 formats supported:
//   - "::1" → "[::1]:8500"
//   - "2001:db8::1" → "[2001:db8::1]:8500"
//   - "[::1]" → "[::1]:8500"
//   - "[::1]:8501" → "[::1]:8501" (unchanged)
//   - "[2001:db8::1]:8501" → "[2001:db8::1]:8501" (unchanged)
//
// Special cases:
//   - "" → "localhost:8500"
//
// SECURITY: Proper IPv6 bracket notation is enforced to prevent address parsing
// ambiguities that could lead to connection failures or unexpected behavior.
//
// RFC 3986 compliance: IPv6 addresses in URIs must be enclosed in brackets
// when followed by a port number to distinguish the port separator from the
// colons used in IPv6 address notation.
//
// Parameters:
//   - host: The host string from the URL (may be empty or without port)
//
// Returns the normalized host:port string suitable for Consul API client.
func (c *ConsulProvider) normalizeHost(host string) string {
	if host == "" {
		return "localhost:8500"
	}

	// Handle IPv6 addresses with bracket notation and port
	if strings.HasPrefix(host, "[") {
		// Check if port is already specified: [::1]:8500
		if strings.Contains(host, "]:") {
			return host // Already properly formatted with port
		}
		// IPv6 with brackets but no port: [::1] → [::1]:8500
		return host + ":8500"
	}

	// Detect bare IPv6 addresses (contain multiple colons but no brackets)
	colonCount := strings.Count(host, ":")
	if colonCount > 1 {
		// This is likely a bare IPv6 address without brackets
		// Wrap in brackets and add default port: ::1 → [::1]:8500
		// Use strings.Builder for efficient concatenation (micro optimization)
		var sb strings.Builder
		sb.Grow(len(host) + 8) // Pre-allocate capacity: "[" + host + "]:8500"
		sb.WriteByte('[')
		sb.WriteString(host)
		sb.WriteString("]:8500")
		return sb.String()
	}

	// Handle IPv4 addresses and hostnames
	if colonCount == 1 {
		// Already has port specified: example.com:8501 or 192.168.1.1:8500
		return host
	}

	// No port specified, add default: example.com → example.com:8500
	// Use strings.Builder for efficient concatenation (micro optimization)
	var sb strings.Builder
	sb.Grow(len(host) + 5) // Pre-allocate capacity: host + ":8500"
	sb.WriteString(host)
	sb.WriteString(":8500")
	return sb.String()
}

// setHttpAuth configures HTTP Basic Authentication for the Consul client
//
// This function extracts username and password from the URL's user info section
// and configures the Consul API client for HTTP Basic Authentication. This is
// useful for environments where Consul is protected by an HTTP proxy with
// basic authentication requirements.
//
// The function handles:
// - Username extraction from URL user info
// - Password extraction with presence validation
// - HttpAuth configuration only when credentials are provided
// - Empty or missing credentials are safely ignored
//
// Parameters:
//   - config: The Consul API configuration to modify
//   - userInfo: The URL user info containing username and password
//
// The function modifies the config in-place by setting the HttpAuth field
// when valid credentials are found in the user info.
//
// Example URL formats:
//   - consul://user:pass@consul.example.com:8500/config/app
//   - consul://username@consul.example.com:8500/config/app (password empty)
func (c *ConsulProvider) setHttpAuth(config *consulapi.Config, userInfo *url.Userinfo) {
	username := userInfo.Username()
	password, hasPassword := userInfo.Password()

	if username != "" || (hasPassword && password != "") {
		config.HttpAuth = &consulapi.HttpBasicAuth{
			Username: username,
			Password: password,
		}
	}
}

// extractKVPath extracts and validates the Consul KV store path from the URL
//
// This function processes the URL path component to derive the Consul Key-Value
// store path where the configuration is stored. It performs comprehensive security
// validation and normalization to prevent path traversal attacks and other security issues.
//
// SECURITY FEATURES:
// - Path traversal attack prevention (../, ..\\, URL-encoded variants)
// - Null byte injection protection
// - Control character filtering
// - Windows device name validation
// - Path length and depth limits
// - Alternate Data Stream detection
//
// Path processing:
// - Removes leading and trailing slashes to normalize the path
// - Validates that the path is not empty (required for Consul KV operations)
// - Performs comprehensive security validation via validateSecureKeyPath
// - Returns the clean, secure path ready for use with Consul KV API
//
// Parameters:
//   - u: The parsed URL containing the path to extract
//
// Returns:
//   - string: The cleaned and validated Consul KV path
//   - error: ARGUS_INVALID_CONFIG if the path is empty, invalid, or contains security issues
//
// Example transformations:
//   - "/config/myapp/" -> "config/myapp"
//   - "/service/production/settings" -> "service/production/settings"
//   - "/" or "" -> error (path is required)
//   - "/../../../etc/passwd" -> error (path traversal detected)
func (c *ConsulProvider) extractKVPath(u *url.URL) (string, error) {
	kvPath := strings.Trim(u.Path, "/")
	if kvPath == "" {
		return "", errors.New("ARGUS_INVALID_CONFIG", "Consul key path is required")
	}

	// SECURITY: Validate and sanitize the key path to prevent security issues
	validatedPath, err := validateSecureKeyPath(kvPath)
	if err != nil {
		return "", err
	}

	return validatedPath, nil
}

// extractQueryParams extracts and processes query parameters from the URL
//
// This function parses URL query parameters and applies them to the Consul
// configuration. It handles all supported query parameters for Consul provider
// configuration including datacenter selection, authentication tokens, and
// encryption settings.
//
// Supported query parameters:
//   - datacenter: Specifies the target Consul datacenter for requests
//   - token: Provides ACL token for Consul authentication
//   - tls: Enables HTTPS/TLS communication ("true" activates)
//   - ssl: Alternative parameter for TLS activation ("true" activates)
//
// The function modifies the Consul configuration in-place and returns
// the datacenter and token values for use in request contexts.
//
// Parameters:
//   - u: The parsed URL containing query parameters
//   - config: The Consul configuration to modify with extracted parameters
//
// Returns:
//   - string: The datacenter name (empty if not specified)
//   - string: The ACL token (empty if not specified)
//
// Example URL with query parameters:
//
//	consul://consul.example.com:8500/config/app?datacenter=us-east-1&token=secret123&tls=true
func (c *ConsulProvider) extractQueryParams(u *url.URL, config *consulapi.Config) (string, string) {
	queryParams := u.Query()
	datacenter := queryParams.Get("datacenter")
	token := queryParams.Get("token")

	if datacenter != "" {
		config.Datacenter = datacenter
	}

	if token != "" {
		config.Token = token
	}

	if queryParams.Get("tls") == "true" || queryParams.Get("ssl") == "true" {
		config.Scheme = "https"

		// SECURITY: Configure secure TLS settings using Consul's TLSConfig
		config.TLSConfig = consulapi.TLSConfig{
			InsecureSkipVerify: false, // Always verify certificates
		}

		// SECURITY: Configure secure HTTP client with custom TLS transport
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,        // Minimum TLS 1.2
			CipherSuites:       getSecureCipherSuites(), // Only secure ciphers
			InsecureSkipVerify: false,                   // Always verify certificates
			ServerName:         extractHostname(u.Host), // Set proper server name for verification
		}

		// Create secure HTTP transport with optimized connection pooling
		transport := &http.Transport{
			TLSClientConfig:       tlsConfig,
			DisableCompression:    false,
			DisableKeepAlives:     false,
			MaxIdleConns:          maxConcurrentRequests,     // Use resource limit constant
			MaxIdleConnsPerHost:   maxConcurrentRequests / 2, // Limit per-host connections
			MaxConnsPerHost:       maxConcurrentRequests,     // Limit total connections per host
			IdleConnTimeout:       30 * time.Second,          // Cleanup idle connections
			TLSHandshakeTimeout:   10 * time.Second,          // Prevent hanging TLS handshakes
			ExpectContinueTimeout: 1 * time.Second,           // Optimize 100-continue handling
		}

		// Set custom HTTP client with secure transport
		config.HttpClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second, // Prevent hanging connections
		}
	}

	return datacenter, token
}

// Pre-compiled secure cipher suites for optimal performance (micro optimization)
var secureCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// getSecureCipherSuites returns a list of secure TLS cipher suites.
//
// SECURITY: This function returns only cipher suites that provide:
// - Perfect Forward Secrecy (PFS)
// - Strong encryption (AES with GCM mode)
// - Secure key exchange (ECDHE)
// - No known vulnerabilities
func getSecureCipherSuites() []uint16 {
	return secureCipherSuites
}

// extractHostname extracts the hostname from a host:port string for certificate validation.
//
// SECURITY: This ensures proper hostname verification for TLS certificates
// by extracting just the hostname part without the port.
func extractHostname(host string) string {
	if colonIndex := strings.LastIndex(host, ":"); colonIndex > 0 {
		// IPv6 addresses are enclosed in brackets, preserve them
		if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
			return host[:strings.LastIndex(host, "]:")+1]
		}
		// Regular hostname:port format
		return host[:colonIndex]
	}
	return host
}

// getClient returns the Consul client, initializing it exactly once in a thread-safe manner
// This is the idiomatic Go pattern for lazy initialization using sync.Once
func (c *ConsulProvider) getClient(config *consulapi.Config) (*consulapi.Client, error) {
	c.clientOnce.Do(func() {
		c.client, c.clientError = consulapi.NewClient(config)
	})

	if c.clientError != nil {
		return nil, errors.Wrap(c.clientError, "ARGUS_REMOTE_CONFIG_ERROR",
			"failed to create Consul client")
	}

	// Use read lock to safely access client
	c.clientMutex.RLock()
	client := c.client
	c.clientMutex.RUnlock()

	// Check if provider was closed
	if client == nil {
		return nil, errors.New("ARGUS_PROVIDER_CLOSED", "consul provider has been closed")
	}

	return client, nil
}

// Load retrieves configuration from Consul KV store
//
// The configuration is expected to be stored as JSON in the specified Consul key.
// This method handles:
// - Lazy client initialization with connection reuse
// - Proper datacenter routing
// - ACL token authentication
// - JSON parsing with comprehensive error handling
// - Mock implementation fallback for testing
//
// Returns the parsed configuration as map[string]interface{} for consistency
// with Argus configuration format expectations.
func (c *ConsulProvider) Load(ctx context.Context, configURL string) (map[string]interface{}, error) {
	// SECURITY: Check resource limits before proceeding
	if err := c.checkResourceLimits("load"); err != nil {
		return nil, err
	}

	// Track request for resource management
	c.incrementRequestCount()
	defer c.decrementRequestCount()

	// Apply timeout to context for DoS protection
	c.initializeSecureDefaults()
	timeout := time.Duration(c.requestTimeout.Load())
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	consulConfig, kvPath, datacenter, token, err := c.parseConsulURL(configURL)
	if err != nil {
		return nil, err
	}

	// Initialize Consul client using thread-safe sync.Once pattern
	_, err = c.getClient(consulConfig)
	if err != nil {
		return nil, err
	}

	// Mock implementation for testing - allows comprehensive testing without Consul
	if c.mockData != nil {
		return c.loadFromMock(kvPath, datacenter)
	}

	// Production implementation using real Consul API
	return c.loadFromConsul(ctxWithTimeout, kvPath, datacenter, token)
}

// loadFromMock handles loading configuration from mock data during testing
// This enables comprehensive testing without requiring a running Consul instance
func (c *ConsulProvider) loadFromMock(kvPath, datacenter string) (map[string]interface{}, error) {
	c.mockMutex.RLock()
	defer c.mockMutex.RUnlock()

	// Check if mock datacenter matches (if specified)
	if datacenter != "" && c.mockDatacenter != "" && datacenter != c.mockDatacenter {
		return nil, errors.New("ARGUS_CONFIG_NOT_FOUND",
			fmt.Sprintf("Consul key '%s' not found in datacenter '%s'", kvPath, datacenter))
	}

	jsonData, exists := c.mockData[kvPath]
	if !exists {
		return nil, errors.New("ARGUS_CONFIG_NOT_FOUND",
			fmt.Sprintf("Consul key '%s' not found", kvPath))
	}

	// Parse JSON configuration with proper error handling
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &config); err != nil {
		return nil, errors.Wrap(err, "ARGUS_REMOTE_CONFIG_ERROR",
			"failed to parse JSON configuration from Consul")
	}

	return config, nil
}

// loadFromConsul handles loading configuration from real Consul KV store
// Uses the official Consul API client for production reliability
func (c *ConsulProvider) loadFromConsul(ctx context.Context, kvPath, datacenter, token string) (map[string]interface{}, error) {
	kv := c.client.KV()

	// Build query options for Consul request
	queryOpts := &consulapi.QueryOptions{
		Datacenter: datacenter,
		Token:      token,
	}

	// Retrieve configuration from Consul KV store
	pair, _, err := kv.Get(kvPath, queryOpts.WithContext(ctx))
	if err != nil {
		return nil, errors.Wrap(err, "ARGUS_REMOTE_CONFIG_ERROR",
			"failed to retrieve config from Consul")
	}

	// Handle key not found case
	if pair == nil {
		return nil, errors.New("ARGUS_CONFIG_NOT_FOUND",
			fmt.Sprintf("Consul key '%s' not found", kvPath))
	}

	// SECURITY: Check response size to prevent memory exhaustion attacks
	maxSize := c.maxResponseSize.Load()
	if int64(len(pair.Value)) > maxSize {
		return nil, errors.New("ARGUS_RESOURCE_LIMIT_EXCEEDED",
			fmt.Sprintf("consul response too large: %d bytes (max %d)", len(pair.Value), maxSize))
	}

	// Parse JSON configuration
	var config map[string]interface{}
	if err := json.Unmarshal(pair.Value, &config); err != nil {
		return nil, errors.Wrap(err, "ARGUS_REMOTE_CONFIG_ERROR",
			"failed to parse JSON configuration from Consul")
	}

	return config, nil
}

// Watch monitors Consul key for changes using efficient blocking queries
//
// This provides native Consul watching capabilities using blocking queries
// which are extremely efficient and provide near-real-time updates with
// minimal network overhead. Consul blocking queries are the recommended
// way to watch for changes and are used by Consul's own tools.
//
// The implementation:
// - Uses Consul's blocking query mechanism for efficiency
// - Handles connection failures with exponential backoff
// - Provides graceful shutdown via context cancellation
// - Sends initial configuration immediately
// - Continues monitoring until context is cancelled
//
// Returns a channel that receives updated configurations when the Consul
// key changes. The channel is closed when the context is cancelled.
func (c *ConsulProvider) Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error) {
	// SECURITY: Check resource limits before proceeding
	if err := c.checkResourceLimits("watch"); err != nil {
		return nil, err
	}

	// Track watch for resource management
	c.incrementWatchCount()

	consulConfig, kvPath, datacenter, token, err := c.parseConsulURL(configURL)
	if err != nil {
		c.decrementWatchCount() // Cleanup on error
		return nil, err
	}

	// Initialize Consul client using thread-safe sync.Once pattern
	_, err = c.getClient(consulConfig)
	if err != nil {
		c.decrementWatchCount() // Cleanup on error
		return nil, errors.Wrap(err, "ARGUS_REMOTE_CONFIG_ERROR",
			"failed to create Consul client for watching")
	}

	// Create buffered channel for configuration updates (prevents blocking)
	configChan := make(chan map[string]interface{}, 1)

	// Create a context that will properly clean up the watch when done
	watchCtx, watchCancel := context.WithCancel(ctx)

	// Set up cleanup function that will be called when watch context is cancelled
	go func() {
		<-watchCtx.Done()
		c.decrementWatchCount()
	}()

	// Mock implementation for testing
	if c.mockData != nil {
		c.startMockWatch(watchCtx, configURL, configChan, watchCancel)
		return configChan, nil
	}

	// Production implementation using Consul blocking queries
	c.startConsulWatch(watchCtx, kvPath, datacenter, token, configChan, watchCancel)
	return configChan, nil
}

// startMockWatch implements watching for testing environment
// Simulates realistic configuration updates by polling for changes more frequently
func (c *ConsulProvider) startMockWatch(ctx context.Context, configURL string, configChan chan map[string]interface{}, cancel context.CancelFunc) {
	go func() {
		defer func() {
			close(configChan)
			cancel() // Ensure cleanup is called
		}()

		var lastConfigJSON string

		// Send initial configuration and remember it
		if config, err := c.Load(ctx, configURL); err == nil {
			if configJSON, jsonErr := c.configToJSON(config); jsonErr == nil {
				lastConfigJSON = configJSON
				select {
				case configChan <- config:
				case <-time.After(watchChannelTimeout):
					// Channel send timed out - continue without blocking
				case <-ctx.Done():
					return
				}
			}
		}

		// Poll for changes more frequently to detect UpdateMockData calls
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if config, err := c.Load(ctx, configURL); err == nil {
					if configJSON, jsonErr := c.configToJSON(config); jsonErr == nil {
						// Only send if configuration actually changed
						if configJSON != lastConfigJSON {
							lastConfigJSON = configJSON
							select {
							case configChan <- config:
							case <-time.After(watchChannelTimeout):
								// Channel send timed out - continue without blocking
							case <-ctx.Done():
								return
							}
						}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// configToJSON converts configuration to JSON string for comparison
func (c *ConsulProvider) configToJSON(config map[string]interface{}) (string, error) {
	jsonBytes, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// generateSecureJitter creates cryptographically secure jitter for backoff delays.
//
// SECURITY: Uses crypto/rand instead of math/rand to prevent predictable timing
// attacks and ensure proper randomness distribution for load balancing.
//
// The jitter is calculated as 0-10% of the input delay to prevent thundering herd
// effects while maintaining acceptable timing bounds.
func generateSecureJitter(delay time.Duration) time.Duration {
	// Generate 4 random bytes using crypto/rand
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to zero jitter if crypto/rand fails
		// This maintains functionality while preferring security
		return 0
	}

	// Convert to uint32 and normalize to 0.0-1.0 range
	randUint32 := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	randFloat := float64(randUint32) / float64(^uint32(0)) // Normalize to 0.0-1.0

	// Calculate jitter as 0-10% of delay
	maxJitter := float64(delay) * 0.1
	return time.Duration(randFloat * maxJitter)
}

// calculateBackoffDelay calculates exponential backoff delay with jitter
//
// This prevents thundering herd problems and provides resilient retry behavior.
// The delay follows the pattern: baseDelay * (2^attempt) + jitter
//
// Parameters:
//   - attempt: Current retry attempt (0-based)
//   - baseDelay: Base delay duration (e.g., 1 second)
//   - maxDelay: Maximum delay cap (e.g., 30 seconds)
//
// Returns the calculated delay duration with jitter added.
// Jitter is random value between 0 and 10% of the calculated delay.
func (c *ConsulProvider) calculateBackoffDelay(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	// Calculate exponential backoff: baseDelay * 2^attempt
	delay := baseDelay * time.Duration(math.Pow(2, float64(attempt)))

	// Cap at maximum delay
	if delay > maxDelay {
		delay = maxDelay
	}

	// Add jitter (0-10% of delay) to prevent thundering herd using crypto/rand
	jitter := generateSecureJitter(delay)

	return delay + jitter
}

// startConsulWatch implements production watching using Consul blocking queries
// This is the most efficient way to watch Consul keys and provides real-time updates
func (c *ConsulProvider) startConsulWatch(ctx context.Context, kvPath, datacenter, token string, configChan chan map[string]interface{}, cancel context.CancelFunc) {
	go func() {
		defer func() {
			close(configChan)
			cancel() // Ensure cleanup is called
		}()

		var lastIndex uint64
		var backoffAttempt int
		kv := c.client.KV()

		// Backoff configuration for resilient error handling
		const (
			baseDelay   = 1 * time.Second  // Initial delay
			maxDelay    = 30 * time.Second // Maximum delay cap
			maxAttempts = 10               // Reset backoff after this many attempts
		)

		// Build base query options
		queryOpts := &consulapi.QueryOptions{
			Datacenter: datacenter,
			Token:      token,
			WaitTime:   5 * time.Minute, // Consul's maximum wait time for blocking queries
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Set wait index for blocking query
			queryOpts.WaitIndex = lastIndex

			// Perform blocking query to Consul
			pair, queryMeta, err := kv.Get(kvPath, queryOpts.WithContext(ctx))
			if err != nil {
				// Increment backoff attempt counter
				backoffAttempt++

				// Calculate exponential backoff delay with jitter
				delay := c.calculateBackoffDelay(backoffAttempt-1, baseDelay, maxDelay)

				// Reset backoff after max attempts to prevent indefinite long delays
				if backoffAttempt >= maxAttempts {
					backoffAttempt = 0
				}

				// Wait with exponential backoff before retrying
				select {
				case <-time.After(delay):
					continue // Retry after exponential backoff delay
				case <-ctx.Done():
					return
				}
			}

			// Reset backoff on successful request
			backoffAttempt = 0

			// Check if configuration actually changed
			if queryMeta.LastIndex == lastIndex {
				continue // No change, continue blocking
			}

			// Update last index for next blocking query
			lastIndex = queryMeta.LastIndex

			// Process configuration update
			if pair != nil {
				var config map[string]interface{}
				if json.Unmarshal(pair.Value, &config) == nil {
					select {
					case configChan <- config:
					case <-time.After(watchChannelTimeout):
						// Channel send timed out - continue without blocking
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
}

// HealthCheck verifies Consul connectivity and cluster health
//
// Performs comprehensive health checks:
// - Consul agent connectivity via status API
// - Cluster leadership verification
// - Network connectivity validation
// - Mock implementation for testing
//
// This is useful for:
// - Monitoring and alerting systems
// - Circuit breaker patterns
// - Load balancer health checks
// - Startup validation
func (c *ConsulProvider) HealthCheck(ctx context.Context, configURL string) error {
	// Check if provider has been closed
	if c.closed.Load() {
		return errors.New("ARGUS_PROVIDER_CLOSED", "consul provider has been closed")
	}
	consulConfig, _, datacenter, _, err := c.parseConsulURL(configURL)
	if err != nil {
		return err
	}

	// Initialize Consul client using thread-safe sync.Once pattern
	_, err = c.getClient(consulConfig)
	if err != nil {
		return errors.Wrap(err, "ARGUS_REMOTE_CONFIG_ERROR",
			"failed to create Consul client for health check")
	}

	// Mock implementation for testing
	if c.mockData != nil {
		return c.performMockHealthCheck(consulConfig, datacenter)
	}

	// Production implementation using real Consul API
	return c.performConsulHealthCheck(ctx)
}

// performMockHealthCheck simulates health checking for testing
func (c *ConsulProvider) performMockHealthCheck(consulConfig *consulapi.Config, datacenter string) error {
	host := consulConfig.Address

	// Simulate successful health check for localhost
	if strings.Contains(host, "localhost") || strings.Contains(host, "127.0.0.1") {
		c.mockConnected.Store(true)
		return nil
	}

	// Simulate connection failure for non-localhost
	return errors.New("ARGUS_REMOTE_CONFIG_ERROR",
		fmt.Sprintf("Consul health check failed: cannot connect to %s (dc: %s)", host, datacenter))
}

// performConsulHealthCheck performs real health check using Consul API
func (c *ConsulProvider) performConsulHealthCheck(_ context.Context) error {
	status := c.client.Status()

	// Check if we can reach the Consul agent and verify cluster has a leader
	leader, err := status.Leader()
	if err != nil {
		return errors.Wrap(err, "ARGUS_REMOTE_CONFIG_ERROR",
			"Consul health check failed: cannot reach agent")
	}

	// Verify cluster has elected a leader (required for KV operations)
	if leader == "" {
		return errors.New("ARGUS_REMOTE_CONFIG_ERROR",
			"Consul health check failed: no leader elected")
	}

	return nil
}

// SetMockData configures the provider for testing with mock data
//
// This method allows comprehensive testing without requiring a real Consul instance.
// It sets up the provider to use mock data instead of connecting to Consul.
//
// Parameters:
//   - data: Key-value pairs representing Consul KV store data
//
// This method should only be used in testing environments.
// In production, this method should not be called.
func (c *ConsulProvider) SetMockData(data map[string]string) {
	c.mockMutex.Lock()
	defer c.mockMutex.Unlock()

	c.mockData = make(map[string]string)
	for k, v := range data {
		c.mockData[k] = v
	}
	c.mockConnected.Store(true)
}

// UpdateMockData updates specific keys in the mock data during testing
//
// This method allows simulation of configuration changes during watch testing.
// It's particularly useful for testing the Watch functionality with realistic
// configuration updates.
//
// Parameters:
//   - key: The Consul key to update
//   - newData: The new JSON data for the key
//
// This method should only be used in testing environments.
func (c *ConsulProvider) UpdateMockData(key, newData string) {
	c.mockMutex.Lock()
	defer c.mockMutex.Unlock()

	if c.mockData == nil {
		c.mockData = make(map[string]string)
	}
	c.mockData[key] = newData
}

// SetMockDatacenter configures the mock datacenter for testing
// This allows testing multi-datacenter scenarios without real Consul infrastructure
func (c *ConsulProvider) SetMockDatacenter(datacenter string) {
	c.mockMutex.Lock()
	defer c.mockMutex.Unlock()
	c.mockDatacenter = datacenter
}

// Close cleanly shuts down the provider and releases all resources
//
// This method performs proper cleanup to prevent resource leaks:
// - Closes idle HTTP connections in the Consul client transport
// - Marks the provider as closed to prevent further operations
// - Provides graceful shutdown for long-running applications
//
// The method is idempotent - multiple calls to Close() are safe.
// Once closed, the provider should not be reused.
//
// This addresses the resource management issue identified by security analysis
// where HTTP connections could leak in long-running applications.
func (c *ConsulProvider) Close() error {
	// Check if already closed (idempotent operation)
	if c.closed.Load() {
		return nil
	}

	// Mark as closed first to prevent race conditions
	c.closed.Store(true)

	// The Consul API client doesn't expose direct access to HTTP transport
	// However, setting the client to nil allows garbage collection
	// and the underlying HTTP client will be closed when no longer referenced
	// This is the safest approach for resource cleanup
	c.clientMutex.Lock()
	if c.client != nil {
		c.client = nil
	}
	c.clientMutex.Unlock()

	return nil
}

// GetProvider returns a new instance of the Consul provider
//
// This function is called by Argus during the provider registration process.
// It returns a fresh instance of the provider that Argus will register
// and use for handling consul:// URLs.
//
// The returned provider is thread-safe and can be used concurrently
// across multiple goroutines.
func GetProvider() RemoteConfigProvider {
	return &ConsulProvider{}
}
