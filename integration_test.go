// integration_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"testing"
	"time"
)

// TestIntegration_Provider_BasicFunctionality tests core provider functionality
func TestIntegration_Provider_BasicFunctionality(t *testing.T) {
	provider := GetProvider()

	// Test Name
	name := provider.Name()
	if name == "" {
		t.Fatal("Provider Name() returned empty string")
	}
	t.Logf("Provider name: %s", name)

	// Test Scheme
	scheme := provider.Scheme()
	if scheme != "consul" {
		t.Fatalf("Expected scheme 'consul', got '%s'", scheme)
	}
	t.Logf("Provider scheme: %s", scheme)

	// Test Validate with valid URL
	validURL := "consul://localhost:8500/config/test"
	if err := provider.Validate(validURL); err != nil {
		t.Fatalf("Validation failed for valid URL: %v", err)
	}
	t.Log("URL validation passed")

	// Test Validate with invalid URL
	invalidURL := "invalid://url"
	if err := provider.Validate(invalidURL); err == nil {
		t.Fatal("Validation should have failed for invalid URL")
	}
	t.Log("Invalid URL correctly rejected")
}

// TestIntegration_Provider_MockOperations tests mock operations
func TestIntegration_Provider_MockOperations(t *testing.T) {
	provider := &ConsulProvider{}

	// Setup mock data
	mockData := map[string]string{
		"config/app":  `{"database": {"host": "localhost", "port": 5432}, "cache": {"ttl": 300}}`,
		"config/auth": `{"jwt_secret": "test-secret", "expiry": "24h"}`,
	}
	provider.SetMockData(mockData)
	provider.SetMockDatacenter("dc1")

	ctx := context.Background()

	// Test Load
	config, err := provider.Load(ctx, "consul://localhost:8500/config/app?datacenter=dc1")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	database, ok := config["database"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected database config to be a map")
	}

	if database["host"] != "localhost" {
		t.Fatalf("Expected host 'localhost', got %v", database["host"])
	}
	t.Log("Mock Load operation successful")

	// Test Watch
	watchChan, err := provider.Watch(ctx, "consul://localhost:8500/config/app")
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// Receive initial config
	select {
	case initialConfig := <-watchChan:
		if initialConfig == nil {
			t.Fatal("Expected initial config, got nil")
		}
		t.Log("Mock Watch operation successful - received initial config")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for initial config from watch")
	}

	// Test HealthCheck
	if err := provider.HealthCheck(ctx, "consul://localhost:8500/config/app"); err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
	t.Log("Mock HealthCheck successful")
}

// TestIntegration_Provider_ErrorHandling tests error scenarios
func TestIntegration_Provider_ErrorHandling(t *testing.T) {
	provider := &ConsulProvider{}
	ctx := context.Background()

	// Test Load with empty mock data (should fail)
	_, err := provider.Load(ctx, "consul://localhost:8500/nonexistent")
	if err == nil {
		t.Fatal("Expected error for nonexistent key, got nil")
	}
	t.Logf("Correctly handled nonexistent key: %v", err)

	// Test invalid JSON in mock data
	provider.SetMockData(map[string]string{
		"invalid": "{ invalid json }",
	})

	_, err = provider.Load(ctx, "consul://localhost:8500/invalid")
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	t.Logf("Correctly handled invalid JSON: %v", err)

	// Test datacenter mismatch
	provider.SetMockData(map[string]string{"config": "{}"})
	provider.SetMockDatacenter("dc1")

	_, err = provider.Load(ctx, "consul://localhost:8500/config?datacenter=dc2")
	if err == nil {
		t.Fatal("Expected error for datacenter mismatch, got nil")
	}
	t.Logf("Correctly handled datacenter mismatch: %v", err)
}

// TestIntegration_Provider_URLParsing tests comprehensive URL parsing
func TestIntegration_Provider_URLParsing(t *testing.T) {
	provider := &ConsulProvider{}

	testCases := []struct {
		name        string
		url         string
		expectError bool
		description string
	}{
		{
			name:        "BasicURL",
			url:         "consul://localhost:8500/config/app",
			expectError: false,
			description: "Basic Consul URL",
		},
		{
			name:        "URLWithAuth",
			url:         "consul://user:pass@localhost:8500/config/app",
			expectError: false,
			description: "URL with HTTP Basic Auth",
		},
		{
			name:        "URLWithDatacenter",
			url:         "consul://localhost:8500/config/app?datacenter=dc1",
			expectError: false,
			description: "URL with datacenter parameter",
		},
		{
			name:        "URLWithToken",
			url:         "consul://localhost:8500/config/app?token=secret123",
			expectError: false,
			description: "URL with ACL token",
		},
		{
			name:        "URLWithTLS",
			url:         "consul://localhost:8500/config/app?tls=true",
			expectError: false,
			description: "URL with TLS enabled",
		},
		{
			name:        "ComplexURL",
			url:         "consul://admin:secret@consul.example.com:8500/service/production/config?datacenter=dc1&token=abc123&tls=true",
			expectError: false,
			description: "Complex URL with all parameters",
		},
		{
			name:        "InvalidScheme",
			url:         "redis://localhost:6379/config",
			expectError: true,
			description: "Wrong scheme should fail",
		},
		{
			name:        "EmptyPath",
			url:         "consul://localhost:8500",
			expectError: true,
			description: "Missing path should fail",
		},
		{
			name:        "EmptyPath2",
			url:         "consul://localhost:8500/",
			expectError: true,
			description: "Empty path should fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := provider.Validate(tc.url)

			if tc.expectError && err == nil {
				t.Errorf("Expected error for %s (%s), but validation passed", tc.name, tc.description)
			}

			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error for %s (%s): %v", tc.name, tc.description, err)
			}

			t.Logf("URL: %s - %s: %s", tc.url, tc.description,
				func() string {
					if err != nil {
						return "FAILED ✗"
					}
					return "PASSED ✓"
				}())
		})
	}
}

// TestIntegration_Provider_Concurrency tests thread safety
func TestIntegration_Provider_Concurrency(t *testing.T) {
	provider := &ConsulProvider{}
	provider.SetMockData(map[string]string{
		"config/test": `{"counter": 0}`,
	})

	ctx := context.Background()
	const numGoroutines = 10
	results := make(chan error, numGoroutines)

	// Test concurrent Load operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			_, err := provider.Load(ctx, "consul://localhost:8500/config/test")
			results <- err
		}(i)
	}

	// Check results
	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Fatalf("Concurrent Load %d failed: %v", i, err)
		}
	}
	t.Log("Concurrent Load operations successful")

	// Test concurrent Validate operations
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			err := provider.Validate("consul://localhost:8500/config/test")
			results <- err
		}(i)
	}

	// Check results
	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Fatalf("Concurrent Validate %d failed: %v", i, err)
		}
	}
	t.Log("Concurrent Validate operations successful")
}
