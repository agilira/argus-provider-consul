// mock_provider_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestConsulProvider_RealisticWatch tests the enhanced mock watch functionality
// This demonstrates how UpdateMockData enables realistic watch testing
func TestConsulProvider_RealisticWatch(t *testing.T) {
	provider := &ConsulProvider{}

	// Initial configuration
	initialConfig := `{"version": 1, "debug": false, "feature_flags": {"analytics": true}}`
	provider.SetMockData(map[string]string{
		"config/service": initialConfig,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start watching
	configChan, err := provider.Watch(ctx, "consul://localhost:8500/config/service")
	if err != nil {
		t.Fatalf("Failed to start watch: %v", err)
	}

	// Receive initial configuration
	select {
	case config := <-configChan:
		if config == nil {
			t.Fatal("Expected initial config, got nil")
		}

		version, ok := config["version"].(float64)
		if !ok || version != 1 {
			t.Fatalf("Expected version 1, got %v", config["version"])
		}

		debug, ok := config["debug"].(bool)
		if !ok || debug != false {
			t.Fatalf("Expected debug false, got %v", config["debug"])
		}

		t.Log("✓ Received initial configuration")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for initial configuration")
	}

	// Schedule configuration updates to simulate real changes
	go func() {
		time.Sleep(500 * time.Millisecond)

		// Update 1: Enable debug mode
		updatedConfig1 := `{"version": 2, "debug": true, "feature_flags": {"analytics": true, "reporting": false}}`
		provider.UpdateMockData("config/service", updatedConfig1)
		t.Log("Updated config: enabled debug mode")

		time.Sleep(1 * time.Second)

		// Update 2: Add new feature
		updatedConfig2 := `{"version": 3, "debug": true, "feature_flags": {"analytics": false, "reporting": true, "new_feature": true}}`
		provider.UpdateMockData("config/service", updatedConfig2)
		t.Log("Updated config: added new feature")

		time.Sleep(1 * time.Second)

		// Update 3: Configuration rollback
		rollbackConfig := `{"version": 4, "debug": false, "feature_flags": {"analytics": true, "reporting": false}}`
		provider.UpdateMockData("config/service", rollbackConfig)
		t.Log("Updated config: rollback configuration")
	}()

	// Track received updates
	updateCount := 0
	expectedUpdates := 3 // We expect 3 updates after the initial configuration

	for updateCount < expectedUpdates {
		select {
		case config := <-configChan:
			if config == nil {
				t.Log("Watch channel closed")
				return
			}

			updateCount++
			version := config["version"].(float64)
			debug := config["debug"].(bool)

			t.Logf("✓ Update #%d: version=%.0f, debug=%t", updateCount, version, debug)

			// Validate specific updates
			switch updateCount {
			case 1:
				if version != 2 || !debug {
					t.Errorf("Update 1: expected version=2, debug=true, got version=%.0f, debug=%t", version, debug)
				}
			case 2:
				if version != 3 {
					t.Errorf("Update 2: expected version=3, got %.0f", version)
				}
				// Check new feature
				if featureFlags, ok := config["feature_flags"].(map[string]interface{}); ok {
					if newFeature, exists := featureFlags["new_feature"]; !exists || newFeature != true {
						t.Errorf("Update 2: expected new_feature=true, got %v", newFeature)
					}
				}
			case 3:
				if version != 4 || debug {
					t.Errorf("Update 3: expected version=4, debug=false, got version=%.0f, debug=%t", version, debug)
				}
			}

		case <-time.After(3 * time.Second):
			t.Fatalf("Timeout waiting for update #%d", updateCount+1)
		}
	}

	t.Logf("✓ Successfully received all %d expected updates", expectedUpdates)
}

// TestConsulProvider_ConcurrentMockUpdates tests concurrent access to mock data
func TestConsulProvider_ConcurrentMockUpdates(t *testing.T) {
	provider := &ConsulProvider{}

	provider.SetMockData(map[string]string{
		"config/test": `{"counter": 0}`,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watching
	configChan, err := provider.Watch(ctx, "consul://localhost:8500/config/test")
	if err != nil {
		t.Fatalf("Failed to start watch: %v", err)
	}

	// Receive initial config
	select {
	case <-configChan:
		t.Log("✓ Received initial configuration")
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for initial configuration")
	}

	// Concurrent updates
	const numUpdates = 5
	updateDone := make(chan bool, numUpdates)

	for i := 1; i <= numUpdates; i++ {
		go func(updateID int) {
			time.Sleep(time.Duration(updateID*100) * time.Millisecond)
			updatedConfig := fmt.Sprintf(`{"counter": %d, "timestamp": "%d"}`, updateID, time.Now().Unix())
			provider.UpdateMockData("config/test", updatedConfig)
			updateDone <- true
		}(i)
	}

	// Wait for all updates to complete
	for i := 0; i < numUpdates; i++ {
		<-updateDone
	}

	// Receive some updates (we may not receive all due to timing)
	receivedUpdates := 0
	timeout := time.After(2 * time.Second)

updateLoop:
	for {
		select {
		case config := <-configChan:
			if config == nil {
				break updateLoop
			}
			receivedUpdates++
			if counter, ok := config["counter"].(float64); ok {
				t.Logf("Received update with counter: %.0f", counter)
			}
		case <-timeout:
			break updateLoop
		}
	}

	if receivedUpdates == 0 {
		t.Error("Expected to receive at least one update")
	} else {
		t.Logf("✓ Received %d updates from concurrent operations", receivedUpdates)
	}
}

// TestConsulProvider_MockDataThreadSafety tests thread safety of mock data operations
func TestConsulProvider_MockDataThreadSafety(t *testing.T) {
	provider := &ConsulProvider{}

	// Initial data
	provider.SetMockData(map[string]string{
		"config/shared": `{"value": "initial"}`,
	})

	const numGoroutines = 10
	const operationsPerGoroutine = 20

	// Concurrent read/write operations
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			ctx := context.Background()

			for j := 0; j < operationsPerGoroutine; j++ {
				// Alternate between read and update operations
				if j%2 == 0 {
					// Read operation
					_, err := provider.Load(ctx, "consul://localhost:8500/config/shared")
					if err != nil {
						t.Errorf("Goroutine %d: Load failed: %v", goroutineID, err)
					}
				} else {
					// Update operation
					newValue := fmt.Sprintf(`{"value": "g%d_op%d", "timestamp": %d}`, goroutineID, j, time.Now().UnixNano())
					provider.UpdateMockData("config/shared", newValue)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Final validation
	ctx := context.Background()
	finalConfig, err := provider.Load(ctx, "consul://localhost:8500/config/shared")
	if err != nil {
		t.Fatalf("Final load failed: %v", err)
	}

	if finalConfig["value"] == nil {
		t.Error("Expected final config to have 'value' field")
	} else {
		t.Logf("✓ Thread safety test completed. Final value: %v", finalConfig["value"])
	}
}
