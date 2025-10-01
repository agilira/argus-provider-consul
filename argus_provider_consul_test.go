// argus_provider_consul_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	consulapi "github.com/hashicorp/consul/api"
)

// TestConsulProvider_Name verifica che il provider restituisca il nome corretto
func TestConsulProvider_Name(t *testing.T) {
	provider := &ConsulProvider{}
	expected := "Consul Remote Configuration Provider v1.0"
	actual := provider.Name()

	if actual != expected {
		t.Errorf("Expected name '%s', got '%s'", expected, actual)
	}
}

// TestConsulProvider_Scheme verifica che il provider restituisca lo schema corretto
func TestConsulProvider_Scheme(t *testing.T) {
	provider := &ConsulProvider{}
	expected := "consul"
	actual := provider.Scheme()

	if actual != expected {
		t.Errorf("Expected scheme '%s', got '%s'", expected, actual)
	}
}

// TestConsulProvider_Validate testa la validazione degli URL
func TestConsulProvider_Validate(t *testing.T) {
	provider := &ConsulProvider{}

	testCases := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "Valid basic URL",
			url:         "consul://localhost:8500/config/myapp",
			expectError: false,
		},
		{
			name:        "Valid URL with auth",
			url:         "consul://user:pass@localhost:8500/config/myapp",
			expectError: false,
		},
		{
			name:        "Valid URL with datacenter",
			url:         "consul://localhost:8500/config/myapp?datacenter=dc1",
			expectError: false,
		},
		{
			name:        "Valid URL with token",
			url:         "consul://localhost:8500/config/myapp?token=SECRET",
			expectError: false,
		},
		{
			name:        "Valid URL with TLS",
			url:         "consul://localhost:8500/config/myapp?tls=true",
			expectError: false,
		},
		{
			name:        "Invalid scheme",
			url:         "redis://localhost:8500/config/myapp",
			expectError: true,
		},
		{
			name:        "Missing key path",
			url:         "consul://localhost:8500/",
			expectError: true,
		},
		{
			name:        "Empty key path",
			url:         "consul://localhost:8500",
			expectError: true,
		},
		{
			name:        "Invalid URL format",
			url:         "not-a-url",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := provider.Validate(tc.url)
			if tc.expectError && err == nil {
				t.Errorf("Expected error for URL '%s', but got none", tc.url)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error for URL '%s', but got: %v", tc.url, err)
			}
		})
	}
}

// TestConsulProvider_Load_Mock testa il caricamento con dati mock
func TestConsulProvider_Load_Mock(t *testing.T) {
	provider := &ConsulProvider{}

	// Setup mock data
	mockData := map[string]string{
		"config/myapp": `{"service_name":"test-service","port":8080,"debug":true}`,
		"config/prod":  `{"service_name":"prod-service","port":443,"debug":false}`,
	}
	provider.SetMockData(mockData)

	testCases := []struct {
		name           string
		url            string
		expectedConfig map[string]interface{}
		expectError    bool
	}{
		{
			name: "Load existing config",
			url:  "consul://localhost:8500/config/myapp",
			expectedConfig: map[string]interface{}{
				"service_name": "test-service",
				"port":         float64(8080), // JSON unmarshal converts numbers to float64
				"debug":        true,
			},
			expectError: false,
		},
		{
			name: "Load production config",
			url:  "consul://localhost:8500/config/prod",
			expectedConfig: map[string]interface{}{
				"service_name": "prod-service",
				"port":         float64(443),
				"debug":        false,
			},
			expectError: false,
		},
		{
			name:        "Load non-existent config",
			url:         "consul://localhost:8500/config/nonexistent",
			expectError: true,
		},
		{
			name:        "Invalid URL",
			url:         "invalid-url",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			config, err := provider.Load(ctx, tc.url)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for URL '%s', but got none", tc.url)
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error for URL '%s', but got: %v", tc.url, err)
				return
			}

			if !reflect.DeepEqual(config, tc.expectedConfig) {
				t.Errorf("Config mismatch for URL '%s'.\nExpected: %+v\nActual: %+v",
					tc.url, tc.expectedConfig, config)
			}
		})
	}
}

// TestConsulProvider_Watch_Mock tests watch functionality with mock data
func TestConsulProvider_Watch_Mock(t *testing.T) {
	provider := &ConsulProvider{}

	// Setup mock data
	mockData := map[string]string{
		"config/myapp": `{"service_name":"test-service","port":8080,"debug":true}`,
	}
	provider.SetMockData(mockData)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	configChan, err := provider.Watch(ctx, "consul://localhost:8500/config/myapp")
	if err != nil {
		t.Fatalf("Failed to start watching: %v", err)
	}

	// Should receive initial configuration
	select {
	case config := <-configChan:
		expectedConfig := map[string]interface{}{
			"service_name": "test-service",
			"port":         float64(8080),
			"debug":        true,
		}
		if !reflect.DeepEqual(config, expectedConfig) {
			t.Errorf("Initial config mismatch.\nExpected: %+v\nActual: %+v",
				expectedConfig, config)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for initial configuration")
	}

	// Test configuration update
	go func() {
		time.Sleep(200 * time.Millisecond)
		provider.UpdateMockData("config/myapp", `{"service_name":"updated-service","port":9090,"debug":false}`)
	}()

	// Should receive the update
	select {
	case config := <-configChan:
		if config == nil {
			t.Error("Expected configuration update, got nil")
		}
		serviceName, ok := config["service_name"].(string)
		if !ok || serviceName != "updated-service" {
			t.Errorf("Expected service_name 'updated-service', got %v", config["service_name"])
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for configuration update")
	}
}

// TestConsulProvider_HealthCheck_Mock testa l'health check con mock
func TestConsulProvider_HealthCheck_Mock(t *testing.T) {
	provider := &ConsulProvider{}

	// Setup mock data
	mockData := map[string]string{
		"config/myapp": `{"service_name":"test-service","port":8080,"debug":true}`,
	}
	provider.SetMockData(mockData)

	testCases := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "Localhost health check should succeed",
			url:         "consul://localhost:8500/config/myapp",
			expectError: false,
		},
		{
			name:        "127.0.0.1 health check should succeed",
			url:         "consul://127.0.0.1:8500/config/myapp",
			expectError: false,
		},
		{
			name:        "Remote host health check should fail in mock",
			url:         "consul://remote.consul.com:8500/config/myapp",
			expectError: true,
		},
		{
			name:        "Invalid URL should fail",
			url:         "invalid-url",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			err := provider.HealthCheck(ctx, tc.url)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for URL '%s', but got none", tc.url)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error for URL '%s', but got: %v", tc.url, err)
			}
		})
	}
}

// TestConsulProvider_Datacenter_Mock testa il supporto multi-datacenter
func TestConsulProvider_Datacenter_Mock(t *testing.T) {
	provider := &ConsulProvider{}

	// Setup mock data
	mockData := map[string]string{
		"config/dc1": `{"datacenter":"dc1","replicas":3}`,
	}
	provider.SetMockData(mockData)
	provider.SetMockDatacenter("dc1")

	testCases := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "Matching datacenter should succeed",
			url:         "consul://localhost:8500/config/dc1?datacenter=dc1",
			expectError: false,
		},
		{
			name:        "Non-matching datacenter should fail",
			url:         "consul://localhost:8500/config/dc1?datacenter=dc2",
			expectError: true,
		},
		{
			name:        "No datacenter specified should succeed",
			url:         "consul://localhost:8500/config/dc1",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := provider.Load(ctx, tc.url)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for URL '%s', but got none", tc.url)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error for URL '%s', but got: %v", tc.url, err)
			}
		})
	}
}

// TestGetProvider verifica che GetProvider restituisca un'istanza valida
func TestGetProvider(t *testing.T) {
	provider := GetProvider()
	if provider == nil {
		t.Error("GetProvider returned nil")
	}

	// Verifica che sia del tipo corretto
	if _, ok := provider.(*ConsulProvider); !ok {
		t.Errorf("GetProvider returned wrong type: %T", provider)
	}

	// Verifica che implementi l'interfaccia
	var _ RemoteConfigProvider = provider
}

// TestConsulProvider_parseConsulURL_EdgeCases testa casi edge del parser URL
func TestConsulProvider_parseConsulURL_EdgeCases(t *testing.T) {
	provider := &ConsulProvider{}

	testCases := []struct {
		name          string
		url           string
		expectedHost  string
		expectedPath  string
		expectedDC    string
		expectedToken string
		expectError   bool
	}{
		{
			name:         "Default port added",
			url:          "consul://consul.example.com/config/test",
			expectedHost: "consul.example.com:8500",
			expectedPath: "config/test",
			expectError:  false,
		},
		{
			name:         "Custom port preserved",
			url:          "consul://consul.example.com:9500/config/test",
			expectedHost: "consul.example.com:9500",
			expectedPath: "config/test",
			expectError:  false,
		},
		{
			name:         "Datacenter parameter",
			url:          "consul://localhost:8500/config/test?datacenter=production",
			expectedHost: "localhost:8500",
			expectedPath: "config/test",
			expectedDC:   "production",
			expectError:  false,
		},
		{
			name:          "Token parameter",
			url:           "consul://localhost:8500/config/test?token=secret-token-123",
			expectedHost:  "localhost:8500",
			expectedPath:  "config/test",
			expectedToken: "secret-token-123",
			expectError:   false,
		},
		{
			name:          "Multiple parameters",
			url:           "consul://localhost:8500/config/test?datacenter=dc1&token=ABC123&tls=true",
			expectedHost:  "localhost:8500",
			expectedPath:  "config/test",
			expectedDC:    "dc1",
			expectedToken: "ABC123",
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config, path, dc, token, err := provider.parseConsulURL(tc.url)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for URL '%s', but got none", tc.url)
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error for URL '%s', but got: %v", tc.url, err)
				return
			}

			if config.Address != tc.expectedHost {
				t.Errorf("Host mismatch for URL '%s'. Expected: %s, Got: %s",
					tc.url, tc.expectedHost, config.Address)
			}

			if path != tc.expectedPath {
				t.Errorf("Path mismatch for URL '%s'. Expected: %s, Got: %s",
					tc.url, tc.expectedPath, path)
			}

			if dc != tc.expectedDC {
				t.Errorf("Datacenter mismatch for URL '%s'. Expected: %s, Got: %s",
					tc.url, tc.expectedDC, dc)
			}

			if token != tc.expectedToken {
				t.Errorf("Token mismatch for URL '%s'. Expected: %s, Got: %s",
					tc.url, tc.expectedToken, token)
			}
		})
	}
}

// TestConsulProvider_Close tests the Close method for proper resource cleanup
func TestConsulProvider_Close(t *testing.T) {
	provider := &ConsulProvider{}

	// Test multiple calls to Close (should be idempotent)
	err := provider.Close()
	if err != nil {
		t.Errorf("First Close() should not return error, got: %v", err)
	}

	err = provider.Close()
	if err != nil {
		t.Errorf("Second Close() should not return error (idempotent), got: %v", err)
	}

	// Test that operations fail after Close()
	ctx := context.Background()
	testURL := "consul://localhost:8500/config/test"

	_, err = provider.Load(ctx, testURL)
	if err == nil {
		t.Error("Load() should fail after Close()")
	}
	if !strings.Contains(err.Error(), "consul provider has been closed") {
		t.Errorf("Expected error to contain 'consul provider has been closed', got: %v", err)
	}

	_, err = provider.Watch(ctx, testURL)
	if err == nil {
		t.Error("Watch() should fail after Close()")
	}
	if !strings.Contains(err.Error(), "consul provider has been closed") {
		t.Errorf("Expected error to contain 'consul provider has been closed', got: %v", err)
	}

	err = provider.HealthCheck(ctx, testURL)
	if err == nil {
		t.Error("HealthCheck() should fail after Close()")
	}
	if !strings.Contains(err.Error(), "consul provider has been closed") {
		t.Errorf("Expected error to contain 'consul provider has been closed', got: %v", err)
	}
}

// TestConsulProvider_CalculateBackoffDelay tests the exponential backoff calculation
func TestConsulProvider_CalculateBackoffDelay(t *testing.T) {
	provider := &ConsulProvider{}
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second

	testCases := []struct {
		attempt     int
		expectMin   time.Duration
		expectMax   time.Duration
		description string
	}{
		{
			attempt:     0,
			expectMin:   baseDelay,                // 1s base
			expectMax:   baseDelay + baseDelay/10, // 1s + 10% jitter = 1.1s
			description: "First attempt should use base delay",
		},
		{
			attempt:     1,
			expectMin:   2 * baseDelay,                // 2s
			expectMax:   2*baseDelay + 2*baseDelay/10, // 2s + 10% jitter = 2.2s
			description: "Second attempt should double the delay",
		},
		{
			attempt:     2,
			expectMin:   4 * baseDelay,                // 4s
			expectMax:   4*baseDelay + 4*baseDelay/10, // 4s + 10% jitter = 4.4s
			description: "Third attempt should quadruple the delay",
		},
		{
			attempt:     10,
			expectMin:   maxDelay,               // Should be capped at maxDelay
			expectMax:   maxDelay + maxDelay/10, // 30s + 10% jitter = 33s
			description: "High attempt should be capped at max delay",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			delay := provider.calculateBackoffDelay(tc.attempt, baseDelay, maxDelay)

			if delay < tc.expectMin {
				t.Errorf("Delay too short for attempt %d: got %v, expected min %v",
					tc.attempt, delay, tc.expectMin)
			}

			if delay > tc.expectMax {
				t.Errorf("Delay too long for attempt %d: got %v, expected max %v",
					tc.attempt, delay, tc.expectMax)
			}

			t.Logf("Attempt %d: delay = %v (expected range: %v - %v)",
				tc.attempt, delay, tc.expectMin, tc.expectMax)
		})
	}
}

// TestConsulProvider_BackoffJitterVariance tests that jitter provides variance
func TestConsulProvider_BackoffJitterVariance(t *testing.T) {
	provider := &ConsulProvider{}
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second
	attempt := 2

	// Generate multiple delays to check for variance (jitter)
	delays := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		delays[i] = provider.calculateBackoffDelay(attempt, baseDelay, maxDelay)
	}

	// Check that we have variance (not all delays are identical)
	firstDelay := delays[0]
	hasVariance := false
	for i := 1; i < len(delays); i++ {
		if delays[i] != firstDelay {
			hasVariance = true
			break
		}
	}

	if !hasVariance {
		t.Error("Backoff calculation should include jitter for variance, but all delays were identical")
	}

	// Verify all delays are within expected bounds
	expectedBase := 4 * baseDelay // 2^2 * baseDelay
	minExpected := expectedBase
	maxExpected := expectedBase + expectedBase/10 // +10% jitter

	for i, delay := range delays {
		if delay < minExpected || delay > maxExpected {
			t.Errorf("Delay %d out of bounds: got %v, expected %v - %v",
				i, delay, minExpected, maxExpected)
		}
	}
}

// TestExtractHostname_EdgeCases tests the extractHostname function for complete coverage
func TestExtractHostname_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "IPv6 with port in brackets",
			input:    "[::1]:8500",
			expected: "[::1]",
		},
		{
			name:     "IPv6 full address with port",
			input:    "[2001:db8::1]:8500",
			expected: "[2001:db8::1]",
		},
		{
			name:     "Hostname without port",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Just colon",
			input:    ":",
			expected: ":",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHostname(tt.input)
			if result != tt.expected {
				t.Errorf("extractHostname(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestValidateSecureKeyPath_AdditionalCases tests edge cases for validateSecureKeyPath
func TestValidateSecureKeyPath_AdditionalCases(t *testing.T) {
	tests := []struct {
		name      string
		keyPath   string
		shouldErr bool
	}{
		{
			name:      "Mixed case traversal",
			keyPath:   "valid/path/../Sensitive/file",
			shouldErr: true,
		},
		{
			name:      "URL encoded traversal",
			keyPath:   "path/%2E%2E%2Fsecret",
			shouldErr: true,
		},
		{
			name:      "Path with legitimate dots",
			keyPath:   "config/app.production/settings",
			shouldErr: false,
		},
		{
			name:      "Unicode dots",
			keyPath:   "path/\u002E\u002E/secret",
			shouldErr: true,
		},
		{
			name:      "Very long legitimate path",
			keyPath:   "very/long/legitimate/path/with/many/segments/config",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateSecureKeyPath(tt.keyPath)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("validateSecureKeyPath(%q) should have returned error, got none", tt.keyPath)
				}
			} else {
				if err != nil {
					t.Errorf("validateSecureKeyPath(%q) returned unexpected error: %v", tt.keyPath, err)
				}
				if result == "" {
					t.Errorf("validateSecureKeyPath(%q) returned empty string, expected valid path", tt.keyPath)
				}
			}
		})
	}
}

// TestNormalizeHost_EdgeCases tests the normalizeHost method with comprehensive IPv6 support
func TestNormalizeHost_EdgeCases(t *testing.T) {
	provider := &ConsulProvider{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic cases
		{
			name:     "Empty string returns localhost",
			input:    "",
			expected: "localhost:8500",
		},
		{
			name:     "Host without port gets default port",
			input:    "consul-server",
			expected: "consul-server:8500",
		},
		{
			name:     "IPv4 without port gets default port",
			input:    "192.168.1.100",
			expected: "192.168.1.100:8500",
		},
		{
			name:     "Host already with port stays unchanged",
			input:    "consul.example.com:8501",
			expected: "consul.example.com:8501",
		},
		{
			name:     "IPv4 with port stays unchanged",
			input:    "192.168.1.100:8501",
			expected: "192.168.1.100:8501",
		},
		// IPv6 cases - comprehensive testing
		{
			name:     "IPv6 loopback without brackets gets wrapped and port",
			input:    "::1",
			expected: "[::1]:8500",
		},
		{
			name:     "IPv6 full address without brackets gets wrapped and port",
			input:    "2001:db8::1",
			expected: "[2001:db8::1]:8500",
		},
		{
			name:     "IPv6 with brackets but no port gets port added",
			input:    "[::1]",
			expected: "[::1]:8500",
		},
		{
			name:     "IPv6 with brackets and port stays unchanged",
			input:    "[::1]:8501",
			expected: "[::1]:8501",
		},
		{
			name:     "IPv6 full address with brackets and port stays unchanged",
			input:    "[2001:db8::1]:8501",
			expected: "[2001:db8::1]:8501",
		},
		{
			name:     "IPv6 complex address without brackets gets wrapped",
			input:    "fe80::1%lo0",
			expected: "[fe80::1%lo0]:8500",
		},
		{
			name:     "IPv6 with zone ID and brackets gets port",
			input:    "[fe80::1%lo0]",
			expected: "[fe80::1%lo0]:8500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.normalizeHost(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeHost(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestNormalizeHost_RFC3986Compliance tests RFC 3986 compliance for IPv6 addresses
func TestNormalizeHost_RFC3986Compliance(t *testing.T) {
	provider := &ConsulProvider{}

	// Test that all normalized IPv6 addresses are RFC 3986 compliant
	ipv6Tests := []string{
		"::1",
		"2001:db8::1",
		"fe80::1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
	}

	for _, ipv6 := range ipv6Tests {
		t.Run("RFC3986_"+ipv6, func(t *testing.T) {
			result := provider.normalizeHost(ipv6)

			// Should start with [ and contain ]:
			if !strings.HasPrefix(result, "[") {
				t.Errorf("IPv6 result should start with '[': %q", result)
			}
			if !strings.Contains(result, "]:") {
				t.Errorf("IPv6 result should contain ']:': %q", result)
			}

			// Should be parseable as URL
			testURL := "http://" + result + "/test"
			_, err := url.Parse(testURL)
			if err != nil {
				t.Errorf("Normalized IPv6 address should be parseable in URL: %v", err)
			}
		})
	}
}

// TestValidateSecureKeyPath_EnhancedDecoding tests the improved URL decoding system
func TestValidateSecureKeyPath_EnhancedDecoding(t *testing.T) {
	tests := []struct {
		name        string
		keyPath     string
		shouldError bool
		description string
	}{
		{
			name:        "Double encoded path traversal",
			keyPath:     "config/%252E%252E%252Fpasswd",
			shouldError: true,
			description: "Should detect double-encoded ../ sequences",
		},
		{
			name:        "Triple encoded path traversal",
			keyPath:     "config/%25252E%25252E%25252Fpasswd",
			shouldError: true,
			description: "Should detect triple-encoded ../ sequences",
		},
		{
			name:        "Mixed encoding with case variations",
			keyPath:     "config/%2e%2E%2F%2e%2e%2fpasswd",
			shouldError: true,
			description: "Should detect mixed case encoded traversal",
		},
		{
			name:        "Encoded backslash traversal (Windows)",
			keyPath:     "config/%2e%2e%5c%2e%2e%5cpasswd",
			shouldError: true,
			description: "Should detect encoded backslash traversal for Windows",
		},
		{
			name:        "Legitimate encoded characters",
			keyPath:     "config/app%20name/settings",
			shouldError: false,
			description: "Should allow legitimate encoded spaces",
		},
		{
			name:        "Encoded forward slash in legitimate path",
			keyPath:     "config/app%2Fname", // app/name
			shouldError: false,
			description: "Should allow encoded forward slashes in legitimate contexts",
		},
		{
			name:        "Very deep encoding (max iterations test)",
			keyPath:     strings.Repeat("%25", 15) + "2E" + strings.Repeat("%25", 15) + "2E",
			shouldError: false, // Should stop at max iterations and not error
			description: "Should handle deeply nested encoding gracefully",
		},
		{
			name:        "Malformed percent encoding",
			keyPath:     "config/app%gg/settings",
			shouldError: false, // Should not crash on malformed encoding
			description: "Should handle malformed percent encoding gracefully",
		},
		{
			name:        "Unicode normalization attack attempt",
			keyPath:     "config/\u002E\u002E\u002F\u002E\u002E\u002Fpasswd",
			shouldError: true,
			description: "Should detect Unicode-based path traversal",
		},
		{
			name:        "Percent-encoded null byte (safe handling)",
			keyPath:     "config/test%00passwd",
			shouldError: false, // url.QueryUnescape safely handles this by not decoding null bytes
			description: "url.QueryUnescape should safely handle percent-encoded null bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateSecureKeyPath(tt.keyPath)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Test %s failed: expected error but got none. %s",
						tt.name, tt.description)
					t.Logf("Input: %q, Result: %q", tt.keyPath, result)
				}
			} else {
				if err != nil {
					t.Errorf("Test %s failed: unexpected error: %v. %s",
						tt.name, err, tt.description)
					t.Logf("Input: %q", tt.keyPath)
				}
			}
		})
	}
}

// TestValidateSecureKeyPath_DecodingEdgeCases tests specific edge cases in URL decoding
func TestValidateSecureKeyPath_DecodingEdgeCases(t *testing.T) {
	// Test that the new decoding system properly handles iteration limits
	t.Run("MaxIterationLimit", func(t *testing.T) {
		// Create a path that would require many decoding iterations
		deepEncoded := "config"
		for i := 0; i < 20; i++ {
			deepEncoded = url.QueryEscape(deepEncoded)
		}

		// This should not hang or panic, should handle gracefully
		result, err := validateSecureKeyPath(deepEncoded)

		// We don't care about the exact result, just that it doesn't crash
		if err != nil && strings.Contains(err.Error(), "panic") {
			t.Errorf("validateSecureKeyPath panicked on deep encoding: %v", err)
		}
		t.Logf("Deep encoded input handled gracefully, result length: %d", len(result))
	})

	// Test proper URL decoding vs old string replacement method
	t.Run("ProperVsOldDecoding", func(t *testing.T) {
		testPath := "config/%2E%2E%2Fsecret"

		// The new system should properly decode this
		result, err := validateSecureKeyPath(testPath)

		// Should detect the traversal attack
		if err == nil {
			t.Errorf("New decoding system should have detected traversal in %q, got result: %q",
				testPath, result)
		}
	})
}

// TestConfigToJSON_EdgeCases tests edge cases for configToJSON function
func TestConfigToJSON_EdgeCases(t *testing.T) {
	provider := &ConsulProvider{}

	tests := []struct {
		name          string
		config        map[string]interface{}
		shouldError   bool
		expectedError string
	}{
		{
			name: "Normal config",
			config: map[string]interface{}{
				"key1": "value1",
				"key2": 42,
			},
			shouldError: false,
		},
		{
			name:        "Empty config",
			config:      map[string]interface{}{},
			shouldError: false,
		},
		{
			name:        "Nil config",
			config:      nil,
			shouldError: false,
		},
		{
			name: "Config with unmarshalable value",
			config: map[string]interface{}{
				"key1": make(chan int), // Channels can't be marshaled to JSON
			},
			shouldError:   true,
			expectedError: "json: unsupported type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := provider.configToJSON(tt.config)

			if tt.shouldError {
				if err == nil {
					t.Errorf("configToJSON should have failed but returned: %q", result)
				} else if tt.expectedError != "" && !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing %q, got: %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("configToJSON failed unexpectedly: %v", err)
				}
				// Verify it's valid JSON
				var parsed map[string]interface{}
				if err := json.Unmarshal([]byte(result), &parsed); err != nil {
					t.Errorf("Result is not valid JSON: %v", err)
				}
			}
		})
	}
}

// TestGetClient_EdgeCases tests edge cases for getClient function
func TestGetClient_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		provider func() *ConsulProvider
		config   func() *consulapi.Config
	}{
		{
			name: "Multiple concurrent calls should use sync.Once properly",
			provider: func() *ConsulProvider {
				return &ConsulProvider{}
			},
			config: func() *consulapi.Config {
				return &consulapi.Config{
					Address: "localhost:8500",
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := tt.provider()
			config := tt.config()

			// Call getClient multiple times concurrently to test sync.Once
			const numGoroutines = 10
			clients := make([]*consulapi.Client, numGoroutines)
			var wg sync.WaitGroup

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(index int) {
					defer wg.Done()
					client, err := provider.getClient(config)
					if err != nil {
						t.Errorf("getClient failed: %v", err)
						return
					}
					clients[index] = client
				}(i)
			}

			wg.Wait()

			// All clients should be the same instance due to sync.Once
			if clients[0] != nil {
				for i := 1; i < numGoroutines; i++ {
					if clients[i] != clients[0] {
						t.Error("sync.Once not working: different client instances returned")
						break
					}
				}
			}
		})
	}
}
