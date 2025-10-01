// watche_functionality_test.go
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

// TestConsulProvider_RealisticWatch_Refactored tests realistic watch functionality with better structure
func TestConsulProvider_RealisticWatch_Refactored(t *testing.T) {
	provider := setupRealisticWatchProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	configChan := startWatchAndGetInitial(t, provider, ctx)
	scheduleConfigUpdates(t, provider)
	verifyAllUpdates(t, ctx, configChan)
}

func setupRealisticWatchProvider(_ *testing.T) *ConsulProvider {
	provider := &ConsulProvider{}
	initialConfig := `{"version": 1, "debug": false, "feature_flags": {"analytics": true}}`
	provider.SetMockData(map[string]string{
		"config/service": initialConfig,
	})
	return provider
}

func startWatchAndGetInitial(t *testing.T, provider *ConsulProvider, ctx context.Context) <-chan map[string]interface{} {
	configChan, err := provider.Watch(ctx, "consul://localhost:8500/config/service")
	if err != nil {
		t.Fatalf("Failed to start watch: %v", err)
	}

	select {
	case config := <-configChan:
		validateInitialConfig(t, config)
		t.Log("✓ Received initial configuration")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for initial configuration")
	}

	return configChan
}

func validateInitialConfig(t *testing.T, config map[string]interface{}) {
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
}

func scheduleConfigUpdates(t *testing.T, provider *ConsulProvider) {
	updates := []struct {
		delay  time.Duration
		config string
		desc   string
	}{
		{500 * time.Millisecond, `{"version": 2, "debug": true, "feature_flags": {"analytics": true, "reporting": false}}`, "enabled debug mode"},
		{1 * time.Second, `{"version": 3, "debug": true, "feature_flags": {"analytics": false, "reporting": true, "new_feature": "enabled"}}`, "added new feature"},
		{1 * time.Second, `{"version": 4, "debug": false, "feature_flags": {"analytics": true, "reporting": true, "new_feature": "enabled"}, "max_connections": 100}`, "final version"},
	}

	go func() {
		for _, update := range updates {
			time.Sleep(update.delay)
			provider.UpdateMockData("config/service", update.config)
			t.Logf("Updated config: %s", update.desc)
		}
	}()
}

func verifyAllUpdates(t *testing.T, ctx context.Context, configChan <-chan map[string]interface{}) {
	updateCount := 1 // Already received initial config

	for updateCount < 4 {
		select {
		case config := <-configChan:
			if config == nil {
				t.Log("✓ Watch channel closed")
				return
			}

			updateCount++
			validateUpdate(t, config, updateCount)

		case <-ctx.Done():
			t.Fatalf("Context timeout - only received %d updates", updateCount)
		}
	}

	t.Logf("✓ Successfully received all %d configuration updates", updateCount)
}

func validateUpdate(t *testing.T, config map[string]interface{}, updateCount int) {
	version, ok := config["version"].(float64)
	if !ok {
		t.Fatalf("Invalid version in update %d", updateCount)
	}

	t.Logf("✓ Received update %d: version %.0f", updateCount, version)

	switch updateCount {
	case 2:
		validateDebugUpdate(t, config)
	case 3:
		validateNewFeatureUpdate(t, config)
	case 4:
		validateFinalUpdate(t, config)
	}
}

func validateDebugUpdate(t *testing.T, config map[string]interface{}) {
	debug, ok := config["debug"].(bool)
	if !ok || !debug {
		t.Fatalf("Expected debug=true in update 2, got %v", config["debug"])
	}
}

func validateNewFeatureUpdate(t *testing.T, config map[string]interface{}) {
	featureFlags, ok := config["feature_flags"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected feature_flags in update 3")
	}

	newFeature, exists := featureFlags["new_feature"]
	if !exists || newFeature != "enabled" {
		t.Fatalf("Expected new_feature=enabled in update 3, got %v", newFeature)
	}
}

func validateFinalUpdate(t *testing.T, config map[string]interface{}) {
	maxConn, ok := config["max_connections"].(float64)
	if !ok || maxConn != 100 {
		t.Fatalf("Expected max_connections=100 in update 4, got %v", config["max_connections"])
	}
}
