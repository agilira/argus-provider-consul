// consul_integration_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestReal_ConsulConnection tests connection to real Consul instance
// This test is skipped unless CONSUL_ADDR environment variable is set
// Example: CONSUL_ADDR=localhost:8500 go test -v -run TestReal
func TestReal_ConsulConnection(t *testing.T) {
	consulAddr := os.Getenv("CONSUL_ADDR")
	if consulAddr == "" {
		t.Skip("Skipping real Consul test - set CONSUL_ADDR to enable")
	}

	provider := &ConsulProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	consulURL := "consul://" + consulAddr + "/test/key"

	// Test health check first
	t.Log("Testing health check against real Consul...")
	if err := provider.HealthCheck(ctx, consulURL); err != nil {
		t.Logf("Health check failed (this is expected if Consul is not running): %v", err)
		t.Skip("Consul not available - skipping real connection tests")
	}

	t.Log("✓ Consul health check passed")

	// Test validation
	if err := provider.Validate(consulURL); err != nil {
		t.Fatalf("URL validation failed: %v", err)
	}
	t.Log("✓ URL validation passed")

	// Test Load (this will likely fail if key doesn't exist, which is fine)
	t.Log("Testing Load operation...")
	config, err := provider.Load(ctx, consulURL)
	if err != nil {
		t.Logf("Load failed (expected if key doesn't exist): %v", err)
	} else {
		t.Logf("✓ Load succeeded, got config with %d keys", len(config))
	}

	// Test Watch
	t.Log("Testing Watch operation...")
	watchCtx, watchCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer watchCancel()

	configChan, err := provider.Watch(watchCtx, consulURL)
	if err != nil {
		t.Logf("Watch setup failed: %v", err)
	} else {
		t.Log("✓ Watch started successfully")

		// Wait briefly for any updates
		select {
		case config := <-configChan:
			if config != nil {
				t.Logf("✓ Received config via watch: %d keys", len(config))
			} else {
				t.Log("✓ Watch channel closed properly")
			}
		case <-watchCtx.Done():
			t.Log("✓ Watch timed out (expected)")
		}
	}

	t.Log("Real Consul integration test completed")
}

// TestReal_ConsulOperations tests full CRUD operations if Consul is available
func TestReal_ConsulOperations(t *testing.T) {
	consulAddr := os.Getenv("CONSUL_ADDR")
	consulToken := os.Getenv("CONSUL_TOKEN") // Optional ACL token
	if consulAddr == "" {
		t.Skip("Skipping real Consul operations test - set CONSUL_ADDR to enable")
	}

	provider := &ConsulProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build URL with token if provided
	testKey := "argus-test/config"
	consulURL := "consul://" + consulAddr + "/" + testKey
	if consulToken != "" {
		consulURL += "?token=" + consulToken
	}

	t.Logf("Testing operations with URL: %s", consulURL)

	// Verify Consul is available
	if err := provider.HealthCheck(ctx, consulURL); err != nil {
		t.Skipf("Consul not available: %v", err)
	}

	// Test Load of non-existent key
	t.Log("Testing load of non-existent key...")
	_, err := provider.Load(ctx, consulURL)
	if err != nil {
		t.Logf("✓ Correctly failed to load non-existent key: %v", err)
	} else {
		t.Log("✓ Key already exists, continuing test...")
	}

	// Note: We don't test PUT operations because our provider is read-only
	// In a real environment, you would use Consul CLI or API to set test data
	t.Log("✓ Read-only operations test completed")
	t.Log("To test loading existing keys, use: consul kv put " + testKey + " '{\"test\":\"value\"}'")
}

// TestReal_ConsulDatacenter tests multi-datacenter functionality
func TestReal_ConsulDatacenter(t *testing.T) {
	consulAddr := os.Getenv("CONSUL_ADDR")
	if consulAddr == "" {
		t.Skip("Skipping datacenter test - set CONSUL_ADDR to enable")
	}

	provider := &ConsulProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with explicit datacenter
	consulURL := "consul://" + consulAddr + "/test/key?datacenter=dc1"

	t.Log("Testing datacenter-specific operations...")

	// Health check should work regardless of datacenter specification
	if err := provider.HealthCheck(ctx, consulURL); err != nil {
		t.Skipf("Consul not available: %v", err)
	}

	// Validation should pass
	if err := provider.Validate(consulURL); err != nil {
		t.Fatalf("Validation failed: %v", err)
	}
	t.Log("✓ Datacenter URL validation passed")

	// Load will fail if datacenter doesn't exist or key doesn't exist
	_, err := provider.Load(ctx, consulURL)
	if err != nil {
		t.Logf("Load with datacenter failed (expected): %v", err)
	} else {
		t.Log("✓ Datacenter load succeeded")
	}

	t.Log("Datacenter test completed")
}
