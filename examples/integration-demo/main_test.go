// main_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	consul "github.com/agilira/argus-provider-consul"
)

// TestNewMockArgusRegistry verifies MockArgusRegistry creation
func TestNewMockArgusRegistry(t *testing.T) {
	registry := NewMockArgusRegistry()

	if registry == nil {
		t.Fatal("Expected non-nil MockArgusRegistry")
	}

	if registry.providers == nil {
		t.Fatal("Expected initialized providers map")
	}

	if len(registry.providers) != 0 {
		t.Errorf("Expected empty providers map, got %d providers", len(registry.providers))
	}
}

// TestMockArgusRegistry_RegisterProvider verifies provider registration functionality
func TestMockArgusRegistry_RegisterProvider(t *testing.T) {
	registry := NewMockArgusRegistry()

	// Test successful registration
	t.Run("successful_registration", func(t *testing.T) {
		provider := consul.GetProvider()
		err := registry.RegisterProvider(provider)

		if err != nil {
			t.Fatalf("Expected successful registration, got error: %v", err)
		}

		// Verify provider is stored
		if len(registry.providers) != 1 {
			t.Errorf("Expected 1 provider, got %d", len(registry.providers))
		}

		storedProvider, exists := registry.providers["consul"]
		if !exists {
			t.Error("Expected consul provider to be stored")
		}

		if storedProvider != provider {
			t.Error("Stored provider doesn't match registered provider")
		}
	})

	// Test empty scheme rejection
	t.Run("empty_scheme_rejection", func(t *testing.T) {
		registry := NewMockArgusRegistry()
		mockProvider := &mockProviderEmptyScheme{}

		err := registry.RegisterProvider(mockProvider)
		if err == nil {
			t.Fatal("Expected error for empty scheme provider")
		}

		expectedError := "provider scheme cannot be empty"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}
	})

	// Test duplicate registration rejection
	t.Run("duplicate_registration_rejection", func(t *testing.T) {
		registry := NewMockArgusRegistry()
		provider := consul.GetProvider()

		// First registration should succeed
		err := registry.RegisterProvider(provider)
		if err != nil {
			t.Fatalf("First registration failed: %v", err)
		}

		// Second registration should fail
		err = registry.RegisterProvider(provider)
		if err == nil {
			t.Fatal("Expected error for duplicate registration")
		}

		expectedError := "provider for scheme 'consul' already registered"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}
	})
}

// TestMockArgusRegistry_GetProvider verifies provider retrieval functionality
func TestMockArgusRegistry_GetProvider(t *testing.T) {
	registry := NewMockArgusRegistry()
	consulProvider := consul.GetProvider()

	// Test provider not found
	t.Run("provider_not_found", func(t *testing.T) {
		provider, err := registry.GetProvider("nonexistent")

		if err == nil {
			t.Fatal("Expected error for nonexistent provider")
		}

		if provider != nil {
			t.Error("Expected nil provider for nonexistent scheme")
		}

		expectedError := "no provider registered for scheme 'nonexistent'"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}
	})

	// Test successful retrieval
	t.Run("successful_retrieval", func(t *testing.T) {
		// Register provider first
		err := registry.RegisterProvider(consulProvider)
		if err != nil {
			t.Fatalf("Registration failed: %v", err)
		}

		// Retrieve provider
		provider, err := registry.GetProvider("consul")
		if err != nil {
			t.Fatalf("Expected successful retrieval, got error: %v", err)
		}

		if provider == nil {
			t.Fatal("Expected non-nil provider")
		}

		if provider != consulProvider {
			t.Error("Retrieved provider doesn't match registered provider")
		}
	})
}

// TestMockArgusRegistry_LoadRemoteConfig verifies remote config loading
func TestMockArgusRegistry_LoadRemoteConfig(t *testing.T) {
	registry := NewMockArgusRegistry()
	consulProvider := consul.GetProvider()

	// Setup mock data
	if cp, ok := consulProvider.(*consul.ConsulProvider); ok {
		cp.SetMockData(map[string]string{
			"test/config": `{"key": "value", "number": 42, "enabled": true}`,
		})
	}

	err := registry.RegisterProvider(consulProvider)
	if err != nil {
		t.Fatalf("Provider registration failed: %v", err)
	}

	// Test successful config loading
	t.Run("successful_loading", func(t *testing.T) {
		config, err := registry.LoadRemoteConfig("consul://localhost:8500/test/config")
		if err != nil {
			t.Fatalf("Expected successful config loading, got error: %v", err)
		}

		if config == nil {
			t.Fatal("Expected non-nil config")
		}

		// Verify config content
		expectedKeys := []string{"key", "number", "enabled"}
		for _, key := range expectedKeys {
			if _, exists := config[key]; !exists {
				t.Errorf("Expected key '%s' in config", key)
			}
		}

		if config["key"] != "value" {
			t.Errorf("Expected config['key'] = 'value', got '%v'", config["key"])
		}
	})

	// Test invalid URL
	t.Run("invalid_url", func(t *testing.T) {
		config, err := registry.LoadRemoteConfig("invalid-url-no-scheme")

		if err == nil {
			t.Fatal("Expected error for invalid URL")
		}

		if config != nil {
			t.Error("Expected nil config for invalid URL")
		}

		if !strings.Contains(fmt.Sprintf("%v", err), "no scheme in URL") {
			t.Errorf("Expected 'no scheme' error, got: %v", err)
		}
	})

	// Test unregistered scheme
	t.Run("unregistered_scheme", func(t *testing.T) {
		config, err := registry.LoadRemoteConfig("unknown://localhost:8500/test/config")

		if err == nil {
			t.Fatal("Expected error for unregistered scheme")
		}

		if config != nil {
			t.Error("Expected nil config for unregistered scheme")
		}

		expectedError := "no provider registered for scheme 'unknown'"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}
	})
}

// TestMockArgusRegistry_Integration verifies complete integration flow
func TestMockArgusRegistry_Integration(t *testing.T) {
	registry := NewMockArgusRegistry()
	consulProvider := consul.GetProvider()

	// Setup comprehensive mock data
	mockData := map[string]string{
		"config/database": `{
			"host": "localhost",
			"port": 5432,
			"database": "testdb",
			"ssl": true,
			"pool_size": 10
		}`,
		"config/cache": `{
			"redis_url": "redis://localhost:6379",
			"ttl": 3600,
			"max_connections": 100
		}`,
		"service/config": `{
			"log_level": "debug",
			"debug": true,
			"metrics_enabled": false,
			"version": "v1.0.0-test"
		}`,
	}

	if cp, ok := consulProvider.(*consul.ConsulProvider); ok {
		cp.SetMockData(mockData)
	}

	// Complete integration test flow
	t.Run("complete_flow", func(t *testing.T) {
		// Step 1: Register provider
		err := registry.RegisterProvider(consulProvider)
		if err != nil {
			t.Fatalf("Provider registration failed: %v", err)
		}

		// Step 2: Verify provider discovery
		provider, err := registry.GetProvider("consul")
		if err != nil {
			t.Fatalf("Provider discovery failed: %v", err)
		}

		if provider.Name() != "Consul Remote Configuration Provider v1.0" {
			t.Errorf("Expected provider name 'Consul Remote Configuration Provider v1.0', got '%s'", provider.Name())
		}

		// Step 3: Test URL validation
		testURLs := []string{
			"consul://localhost:8500/config/test",
			"consul://user:pass@consul.example.com:8500/service/prod",
			"consul://localhost:8500/config/app?datacenter=dc1",
		}

		for _, url := range testURLs {
			if err := provider.Validate(url); err != nil {
				t.Errorf("URL validation failed for %s: %v", url, err)
			}
		}

		// Step 4: Test configuration loading
		testConfigs := map[string]string{
			"consul://localhost:8500/config/database": "database",
			"consul://localhost:8500/config/cache":    "cache",
			"consul://localhost:8500/service/config":  "service",
		}

		for url, configType := range testConfigs {
			config, err := registry.LoadRemoteConfig(url)
			if err != nil {
				t.Errorf("Config loading failed for %s: %v", url, err)
				continue
			}

			if len(config) == 0 {
				t.Errorf("Expected non-empty config for %s", configType)
			}
		}

		// Step 5: Test health checks
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		for url := range testConfigs {
			if err := provider.HealthCheck(ctx, url); err != nil {
				t.Errorf("Health check failed for %s: %v", url, err)
			}
		}

		// Step 6: Test watching capability (basic check)
		watchCtx, watchCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer watchCancel()

		configChan, err := provider.Watch(watchCtx, "consul://localhost:8500/config/database")
		if err != nil {
			t.Fatalf("Watch setup failed: %v", err)
		}

		// Verify we get at least one config update
		select {
		case config := <-configChan:
			if config == nil {
				t.Error("Expected non-nil config from watch channel")
			} else {
				t.Logf("✓ Received config with %d keys from watch", len(config))
			}
		case <-watchCtx.Done():
			t.Error("Watch timed out without receiving config")
		}
	})
}

// mockProviderEmptyScheme is a test helper for testing empty scheme validation
type mockProviderEmptyScheme struct{}

func (m *mockProviderEmptyScheme) Name() string   { return "Empty Scheme Provider" }
func (m *mockProviderEmptyScheme) Scheme() string { return "" }
func (m *mockProviderEmptyScheme) Load(ctx context.Context, configURL string) (map[string]interface{}, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockProviderEmptyScheme) Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockProviderEmptyScheme) Validate(configURL string) error {
	return fmt.Errorf("not implemented")
}
func (m *mockProviderEmptyScheme) HealthCheck(ctx context.Context, configURL string) error {
	return fmt.Errorf("not implemented")
}

// TestMockProviderInterface verifies that our mock provider implements the interface correctly
func TestMockProviderInterface(t *testing.T) {
	var _ RemoteConfigProvider = &mockProviderEmptyScheme{}
	t.Log("✓ Mock provider implements RemoteConfigProvider interface")
}

// BenchmarkMockArgusRegistry_Operations benchmarks registry operations
func BenchmarkMockArgusRegistry_Operations(b *testing.B) {
	registry := NewMockArgusRegistry()
	provider := consul.GetProvider()

	// Setup
	if cp, ok := provider.(*consul.ConsulProvider); ok {
		cp.SetMockData(map[string]string{
			"benchmark/config": `{"benchmark": true, "iterations": 1000}`,
		})
	}

	err := registry.RegisterProvider(provider)
	if err != nil {
		b.Fatalf("Provider registration failed: %v", err)
	}

	b.Run("GetProvider", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := registry.GetProvider("consul")
			if err != nil {
				b.Fatalf("GetProvider failed: %v", err)
			}
		}
	})

	b.Run("LoadRemoteConfig", func(b *testing.B) {
		url := "consul://localhost:8500/benchmark/config"
		for i := 0; i < b.N; i++ {
			_, err := registry.LoadRemoteConfig(url)
			if err != nil {
				b.Fatalf("LoadRemoteConfig failed: %v", err)
			}
		}
	})
}
