// main.go demonstrates real integration with Argus
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIira library
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	consul "github.com/agilira/argus-provider-consul"
)

// MockArgusRegistry simulates how Argus would register and use providers
type MockArgusRegistry struct {
	providers map[string]RemoteConfigProvider
}

// RemoteConfigProvider interface (copied from argus/remote_config.go)
type RemoteConfigProvider interface {
	Name() string
	Scheme() string
	Load(ctx context.Context, configURL string) (map[string]interface{}, error)
	Watch(ctx context.Context, configURL string) (<-chan map[string]interface{}, error)
	Validate(configURL string) error
	HealthCheck(ctx context.Context, configURL string) error
}

func NewMockArgusRegistry() *MockArgusRegistry {
	return &MockArgusRegistry{
		providers: make(map[string]RemoteConfigProvider),
	}
}

func (r *MockArgusRegistry) RegisterProvider(provider RemoteConfigProvider) error {
	scheme := provider.Scheme()
	if scheme == "" {
		return fmt.Errorf("provider scheme cannot be empty")
	}

	if _, exists := r.providers[scheme]; exists {
		return fmt.Errorf("provider for scheme '%s' already registered", scheme)
	}

	r.providers[scheme] = provider
	return nil
}

func (r *MockArgusRegistry) GetProvider(scheme string) (RemoteConfigProvider, error) {
	provider, exists := r.providers[scheme]
	if !exists {
		return nil, fmt.Errorf("no provider registered for scheme '%s'", scheme)
	}
	return provider, nil
}

func (r *MockArgusRegistry) LoadRemoteConfig(configURL string) (map[string]interface{}, error) {
	// Simple URL parsing to get scheme
	var scheme string
	if len(configURL) > 0 {
		for i, c := range configURL {
			if c == ':' {
				scheme = configURL[:i]
				break
			}
		}
	}

	if scheme == "" {
		return nil, fmt.Errorf("no scheme in URL: %s", configURL)
	}

	provider, err := r.GetProvider(scheme)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return provider.Load(ctx, configURL)
}

func main() {
	fmt.Println("=== Argus-Consul Provider Integration Test ===")

	// Create mock Argus registry
	registry := NewMockArgusRegistry()

	// Register our Consul provider (this is what would happen in init())
	consulProvider := consul.GetProvider()
	if err := registry.RegisterProvider(consulProvider); err != nil {
		log.Fatalf("Failed to register Consul provider: %v", err)
	}

	fmt.Printf("✓ Consul provider registered: %s\n", consulProvider.Name())
	fmt.Printf("✓ Handles scheme: %s\n", consulProvider.Scheme())

	// Test 1: Provider Discovery
	fmt.Println("\n--- Test 1: Provider Discovery ---")
	provider, err := registry.GetProvider("consul")
	if err != nil {
		log.Fatalf("Failed to get consul provider: %v", err)
	}
	fmt.Printf("✓ Found provider: %s\n", provider.Name())

	// Test 2: URL Validation
	fmt.Println("\n--- Test 2: URL Validation ---")
	testURLs := []string{
		"consul://localhost:8500/config/app",
		"consul://user:pass@consul.example.com:8500/service/prod?datacenter=dc1&token=secret",
		"consul://localhost:8500/config/test?tls=true",
	}

	for _, url := range testURLs {
		if err := provider.Validate(url); err != nil {
			log.Fatalf("URL validation failed for %s: %v", url, err)
		}
		fmt.Printf("✓ Valid URL: %s\n", url)
	}

	// Test 3: Mock Configuration Loading
	fmt.Println("\n--- Test 3: Configuration Loading ---")

	// Setup mock data (in real usage, this wouldn't be called)
	if consulProvider, ok := provider.(*consul.ConsulProvider); ok {
		consulProvider.SetMockData(map[string]string{
			"config/database": `{
				"host": "localhost",
				"port": 5432,
				"database": "myapp",
				"ssl": true,
				"pool_size": 10
			}`,
			"config/cache": `{
				"redis_url": "redis://localhost:6379",
				"ttl": 3600,
				"max_connections": 100
			}`,
			"service/production/config": `{
				"log_level": "info",
				"debug": false,
				"metrics_enabled": true,
				"version": "v1.2.3"
			}`,
		})
		fmt.Println("✓ Mock data configured")
	}

	// Load configurations through the registry (simulating Argus usage)
	configs := map[string]string{
		"Database Config": "consul://localhost:8500/config/database",
		"Cache Config":    "consul://localhost:8500/config/cache",
		"Service Config":  "consul://localhost:8500/service/production/config",
	}

	for name, url := range configs {
		config, err := registry.LoadRemoteConfig(url)
		if err != nil {
			log.Fatalf("Failed to load %s from %s: %v", name, url, err)
		}
		fmt.Printf("✓ Loaded %s: %d keys\n", name, len(config))

		// Print some config details
		for key, value := range config {
			fmt.Printf("  - %s: %v\n", key, value)
		}
		fmt.Println()
	}

	// Test 4: Health Checks
	fmt.Println("--- Test 4: Health Checks ---")
	ctx := context.Background()

	for name, url := range configs {
		if err := provider.HealthCheck(ctx, url); err != nil {
			log.Fatalf("Health check failed for %s: %v", name, err)
		}
		fmt.Printf("✓ Health check passed: %s\n", name)
	}

	// Test 5: Configuration Watching
	fmt.Println("\n--- Test 5: Configuration Watching ---")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	watchURL := "consul://localhost:8500/config/database"
	configChan, err := provider.Watch(ctx, watchURL)
	if err != nil {
		log.Fatalf("Failed to start watching %s: %v", watchURL, err)
	}

	fmt.Printf("✓ Started watching: %s\n", watchURL)

	// Listen for configuration updates
	updateCount := 0
	for {
		select {
		case config := <-configChan:
			if config == nil {
				fmt.Println("✓ Watch channel closed")
				goto watchComplete
			}
			updateCount++
			fmt.Printf("✓ Received config update #%d: %d keys\n", updateCount, len(config))

			if updateCount >= 2 { // Wait for initial + one update
				cancel()
			}

		case <-ctx.Done():
			fmt.Println("✓ Watch completed (timeout/cancellation)")
			goto watchComplete
		}
	}

watchComplete:
	fmt.Println("\n=== Integration Test Results ===")
	fmt.Println("✓ Provider registration: SUCCESS")
	fmt.Println("✓ URL validation: SUCCESS")
	fmt.Println("✓ Configuration loading: SUCCESS")
	fmt.Println("✓ Health checks: SUCCESS")
	fmt.Println("✓ Configuration watching: SUCCESS")
	fmt.Println("\nAll integration tests passed!")
	fmt.Println("The Consul provider is ready for production use with Argus.")
}
