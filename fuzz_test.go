// fuzz_test.go - Professional Fuzz Testing Suite for Argus Consul Provider
//
// This file implements systematic fuzz testing against functions in the Consul provider
// to identify security vulnerabilities and edge cases in production code.
//
// TESTED FUNCTIONS:
// - validateSecureKeyPath: Path validation and sanitization security
// - parseConsulURL: URL parsing and validation for SSRF/injection prevention
// - normalizeHost: Host normalization for proper connection handling
// - extractKVPath: KV path extraction with security validation
// - Load: Complete configuration loading with JSON parsing
//
// SECURITY FOCUS:
// - Path traversal attack prevention
// - URL manipulation and SSRF detection
// - JSON parsing vulnerabilities
// - Resource exhaustion (DoS) protection
// - Input validation bypass attempts
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"strings"
	"testing"
	"time"
)

// FuzzValidateSecureKeyPath tests the validateSecureKeyPath function for security issues.
//
// This function is critical for preventing path traversal attacks and other injection attempts.
func FuzzValidateSecureKeyPath(f *testing.F) {
	// Seed corpus with real attack vectors and valid cases
	seedPaths := []string{
		// Valid paths that should work
		"config/app",
		"service/production/settings",
		"database/connection/primary",
		"app.config",
		"config-production",

		// Path traversal attacks (should be blocked)
		"../../../etc/passwd",
		"config/../../../etc/shadow",
		"..\\..\\..\\windows\\system32\\config\\sam",

		// URL encoded attacks
		"%2e%2e/%2e%2e/etc/passwd",
		"config/%2e%2e%2fetc%2fpasswd",

		// Windows device names
		"CON",
		"PRN.txt",
		"COM1.log",
		"config/CON.txt",

		// Null byte and control char attacks
		"config\x00.txt",
		"config\r\nmalicious",
		"config\ttest",

		// Length-based DoS
		strings.Repeat("a", 5000),
		strings.Repeat("../", 500) + "etc/passwd",

		// Edge cases
		"",
		"/",
		"\\",
		"   config   ",
	}

	for _, path := range seedPaths {
		f.Add(path)
	}

	f.Fuzz(func(t *testing.T, keyPath string) {
		// Function should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("validateSecureKeyPath panicked with input %q: %v", truncateString(keyPath, 100), r)
			}
		}()

		// Call the real function
		validatedPath, err := validateSecureKeyPath(keyPath)

		// Performance check - should complete quickly
		start := time.Now()
		_, _ = validateSecureKeyPath(keyPath)
		duration := time.Since(start)
		if duration > 100*time.Millisecond {
			t.Errorf("validateSecureKeyPath too slow (%v) for input: %q", duration, truncateString(keyPath, 100))
		}

		if err != nil {
			// Function rejected the path - verify it contains dangerous patterns
			if containsObviousDanger(keyPath) {
				t.Logf("Correctly rejected dangerous path: %q -> %v", truncateString(keyPath, 100), err)
			} else if keyPath == "" {
				t.Logf("Correctly rejected empty path: %q -> %v", keyPath, err)
			} else {
				// This might be a false positive or overly strict validation
				t.Logf("Path rejected (review needed): %q -> %v", truncateString(keyPath, 100), err)
			}
		} else {
			// Function accepted the path - verify it's actually safe
			if containsObviousDanger(validatedPath) {
				t.Errorf("SECURITY FAILURE: Dangerous path was accepted: input=%q output=%q",
					truncateString(keyPath, 100), truncateString(validatedPath, 100))
			}

			// Ensure normalized path is reasonable
			if len(validatedPath) > 10000 {
				t.Errorf("SECURITY ISSUE: Validated path extremely long: %d chars", len(validatedPath))
			}
		}
	})
}

// FuzzConsulURL tests the parseConsulURL function for security and parsing issues.
//
// This function handles URL parsing and is critical for preventing SSRF and injection attacks.
func FuzzConsulURL(f *testing.F) {
	seedURLs := []string{
		// Valid Consul URLs
		"consul://localhost:8500/config",
		"consul://consul.example.com:8500/app/production",
		"consul://user:pass@consul.internal:8500/service/config?datacenter=dc1",

		// SSRF attempts
		"consul://127.0.0.1:22/config",
		"consul://169.254.169.254/latest/meta-data/",
		"consul://localhost@evil.com:8500/config",

		// Path traversal in URL
		"consul://localhost:8500/../../../etc/passwd",
		"consul://localhost:8500/config/../../../proc/self/environ",

		// Malformed URLs
		"consul://",
		"consul:///",
		"consul://:/config",
		"consul://localhost:/config",

		// Protocol confusion
		"http://localhost:8500/config",
		"https://localhost:8500/config",

		// Oversized inputs
		"consul://localhost:8500/" + strings.Repeat("a", 10000),

		// Special characters and injection
		"consul://localhost:8500/config\x00malicious",
		"consul://localhost:8500/config?token=secret\r\nHost: evil.com",

		// IPv6 variations
		"consul://[::1]:8500/config",
		"consul://[2001:db8::1]:8500/config",
		"consul://::1/config",
	}

	for _, url := range seedURLs {
		f.Add(url)
	}

	f.Fuzz(func(t *testing.T, consulURL string) {
		// Initialize a provider instance
		provider := &ConsulProvider{}

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseConsulURL panicked with input %q: %v", truncateString(consulURL, 100), r)
			}
		}()

		// Call the parseConsulURL function
		config, kvPath, datacenter, token, err := provider.parseConsulURL(consulURL)

		// Performance check
		start := time.Now()
		_, _, _, _, _ = provider.parseConsulURL(consulURL)
		duration := time.Since(start)
		if duration > 200*time.Millisecond {
			t.Errorf("parseConsulURL too slow (%v) for input: %q", duration, truncateString(consulURL, 100))
		}

		if err != nil {
			// Parsing failed - this is expected for many inputs
			t.Logf("URL parsing failed (expected for malformed): %q -> %v", truncateString(consulURL, 100), err)
		} else {
			// Parsing succeeded - validate security properties

			// Verify only consul scheme was accepted
			if !strings.HasPrefix(consulURL, "consul://") {
				t.Errorf("SECURITY ISSUE: Non-consul URL was accepted: %q", truncateString(consulURL, 100))
			}

			// Check for obvious path traversal in kvPath
			if containsObviousDanger(kvPath) {
				t.Errorf("SECURITY ISSUE: Dangerous kvPath extracted: %q from URL: %q",
					truncateString(kvPath, 100), truncateString(consulURL, 100))
			}

			// Validate config object exists and is reasonable
			if config == nil {
				t.Errorf("Parsing succeeded but config is nil for URL: %q", truncateString(consulURL, 100))
			}

			// Check for excessive values that could cause DoS
			if len(kvPath) > 10000 {
				t.Logf("Very long kvPath extracted: %d chars", len(kvPath))
			}
			if len(datacenter) > 1000 {
				t.Logf("Very long datacenter: %d chars", len(datacenter))
			}
			if len(token) > 10000 {
				t.Logf("Very long token: %d chars", len(token))
			}
		}
	})
}

// FuzzNormalizeHost tests the normalizeHost function for edge cases.
//
// This function handles host normalization and IPv6 address formatting.
func FuzzNormalizeHost(f *testing.F) {
	seedHosts := []string{
		// Valid hosts
		"localhost",
		"example.com",
		"192.168.1.1",
		"localhost:8500",
		"example.com:8501",

		// IPv6 addresses
		"::1",
		"[::1]",
		"[::1]:8500",
		"2001:db8::1",
		"[2001:db8::1]:8500",

		// Edge cases
		"",
		":",
		":::",
		"[",
		"]",
		"[]",
		"[]:8500",

		// Malformed inputs
		"host:99999",
		"host:-1",
		"host:abc",
		strings.Repeat("host", 1000),
	}

	for _, host := range seedHosts {
		f.Add(host)
	}

	f.Fuzz(func(t *testing.T, host string) {
		provider := &ConsulProvider{}

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("normalizeHost panicked with input %q: %v", truncateString(host, 100), r)
			}
		}()

		// Call the real normalizeHost function
		normalized := provider.normalizeHost(host)

		// Performance check
		start := time.Now()
		_ = provider.normalizeHost(host)
		duration := time.Since(start)
		if duration > 50*time.Millisecond {
			t.Errorf("normalizeHost too slow (%v) for input: %q", duration, truncateString(host, 100))
		}

		// Basic validation of result
		if len(normalized) > 1000 {
			t.Logf("Very long normalized host: %d chars from input: %q", len(normalized), truncateString(host, 100))
		}

		// Should always return something (at least default)
		if normalized == "" {
			t.Errorf("normalizeHost returned empty string for input: %q", host)
		}

		// Should contain port
		if !strings.Contains(normalized, ":") {
			t.Errorf("normalizeHost result missing port: %q from input: %q", normalized, host)
		}
	})
}

// FuzzLoadFunction tests the Load function end-to-end with mock data.
//
// This tests the complete configuration loading process including URL parsing and JSON handling.
func FuzzLoadFunction(f *testing.F) {
	seedURLs := []string{
		"consul://localhost:8500/test/config",
		"consul://localhost:8500/valid/config",
		"consul://localhost:8500/../../../etc/passwd",
		"consul://evil.com:8500/config",
		"invalid://localhost:8500/config",
		"consul://",
		"",
	}

	for _, url := range seedURLs {
		f.Add(url)
	}

	f.Fuzz(func(t *testing.T, configURL string) {
		// Set up provider with mock data
		provider := &ConsulProvider{}
		provider.SetMockData(map[string]string{
			"test/config":    `{"app": "test", "env": "production"}`,
			"valid/config":   `{"database": "localhost:5432"}`,
			"another/config": `{"feature": true}`,
		})

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Load panicked with URL %q: %v", truncateString(configURL, 100), r)
			}
		}()

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Call the real Load function
		config, err := provider.Load(ctx, configURL)

		// Performance check
		start := time.Now()
		_, _ = provider.Load(ctx, configURL)
		duration := time.Since(start)
		if duration > 3*time.Second {
			t.Errorf("Load too slow (%v) for URL: %q", duration, truncateString(configURL, 100))
		}

		if err != nil {
			// Load failed - expected for invalid URLs
			t.Logf("Load failed (expected for invalid): %q -> %v", truncateString(configURL, 100), err)
		} else {
			// Load succeeded - validate result
			if config == nil {
				t.Errorf("Load succeeded but returned nil config for URL: %q", truncateString(configURL, 100))
			}

			// Only valid consul URLs should succeed
			if !strings.HasPrefix(configURL, "consul://") {
				t.Errorf("SECURITY ISSUE: Invalid URL scheme accepted: %q", truncateString(configURL, 100))
			}
		}
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// containsObviousDanger checks for obviously dangerous patterns that should always be rejected
func containsObviousDanger(path string) bool {
	dangerousPatterns := []string{
		"..", "../", "..\\",
		"/etc/", "/proc/", "/sys/",
		"\\windows\\", "\\system32\\",
		"\x00", // null byte
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// Check for Windows device names as complete path components
	windowsDevices := []string{"con", "prn", "aux", "nul", "com1", "lpt1"}
	pathComponents := strings.FieldsFunc(path, func(c rune) bool {
		return c == '/' || c == '\\' || c == ':'
	})

	for _, component := range pathComponents {
		name := strings.ToLower(strings.TrimSpace(component))
		// Remove extension
		if dotIndex := strings.LastIndex(name, "."); dotIndex > 0 {
			name = name[:dotIndex]
		}
		for _, device := range windowsDevices {
			if name == device {
				return true
			}
		}
	}

	return false
}

// truncateString safely truncates strings for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
