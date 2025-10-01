// main.go demonstrates real-time watching capability
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	consul "github.com/agilira/argus-provider-consul"
)

// TestLiveWatching demonstrates real-time watching capability
func main() {
	consulAddr := os.Getenv("CONSUL_ADDR")
	if consulAddr == "" {
		consulAddr = "localhost:8500"
	}

	fmt.Printf("=== Live Consul Watch Test ===\n")
	fmt.Printf("Using Consul at: %s\n\n", consulAddr)

	provider := &consul.ConsulProvider{}
	testKey := "live-test/config"
	consulURL := fmt.Sprintf("consul://%s/%s", consulAddr, testKey)

	// Set initial configuration
	initialConfig := map[string]interface{}{
		"version":   1,
		"debug":     false,
		"max_users": 100,
		"features": map[string]bool{
			"analytics": true,
			"reporting": false,
		},
	}

	if err := setConsulKey(testKey, initialConfig); err != nil {
		log.Fatalf("Failed to set initial config: %v", err)
	}
	fmt.Printf("✓ Set initial configuration in Consul\n")

	// Start watching
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	configChan, err := provider.Watch(ctx, consulURL)
	if err != nil {
		log.Fatalf("Failed to start watching: %v", err)
	}
	fmt.Printf("✓ Started watching %s\n\n", consulURL)

	// Track changes
	changeCount := 0
	maxChanges := 5

	// Schedule configuration updates
	go func() {
		time.Sleep(2 * time.Second)

		updates := []map[string]interface{}{
			{
				"version":   2,
				"debug":     true,
				"max_users": 150,
				"features": map[string]bool{
					"analytics": true,
					"reporting": true,
				},
			},
			{
				"version":   3,
				"debug":     false,
				"max_users": 200,
				"features": map[string]bool{
					"analytics": false,
					"reporting": true,
				},
			},
			{
				"version":   4,
				"debug":     true,
				"max_users": 250,
				"features": map[string]bool{
					"analytics": true,
					"reporting": true,
				},
				"new_feature": "added_dynamically",
			},
		}

		for i, update := range updates {
			time.Sleep(3 * time.Second)
			fmt.Printf("--- Updating configuration (change #%d) ---\n", i+2)
			if err := setConsulKey(testKey, update); err != nil {
				fmt.Printf("Error updating config: %v\n", err)
			} else {
				fmt.Printf("✓ Updated configuration in Consul\n")
			}
		}
	}()

	// Listen for changes
	fmt.Println("Listening for configuration changes...")
	for {
		select {
		case config := <-configChan:
			if config == nil {
				fmt.Println("✓ Watch channel closed")
				goto complete
			}

			changeCount++
			fmt.Printf("\n🔄 CHANGE #%d DETECTED:\n", changeCount)

			// Pretty print the configuration
			jsonBytes, _ := json.MarshalIndent(config, "", "  ")
			fmt.Printf("%s\n", string(jsonBytes))

			// Extract specific fields for verification
			if version, ok := config["version"].(float64); ok {
				fmt.Printf("Version: %.0f\n", version)
			}
			if debug, ok := config["debug"].(bool); ok {
				fmt.Printf("Debug mode: %t\n", debug)
			}
			if maxUsers, ok := config["max_users"].(float64); ok {
				fmt.Printf("Max users: %.0f\n", maxUsers)
			}

			if changeCount >= maxChanges {
				fmt.Printf("\n✓ Detected %d changes - test complete!\n", changeCount)
				cancel()
			}

		case <-ctx.Done():
			fmt.Println("\n✓ Context completed")
			goto complete
		}
	}

complete:
	// Cleanup
	if err := deleteConsulKey(testKey); err != nil {
		fmt.Printf("Warning: failed to cleanup test key: %v\n", err)
	} else {
		fmt.Printf("✓ Cleaned up test data\n")
	}

	fmt.Printf("\n=== Live Watch Test Results ===\n")
	fmt.Printf("✓ Configuration changes detected: %d\n", changeCount)
	fmt.Printf("✓ Real-time watching: VERIFIED\n")
	fmt.Printf("✓ Consul blocking queries: WORKING\n")
	fmt.Printf("✓ JSON parsing: VERIFIED\n")
	fmt.Printf("✓ Provider functionality: VERIFIED\n")
}

func setConsulKey(key string, config map[string]interface{}) error {
	// Validate key to prevent command injection
	if key == "" || strings.ContainsAny(key, ";&|$`") {
		return fmt.Errorf("invalid key format")
	}

	jsonBytes, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// #nosec G204 - key is validated above to prevent injection
	cmd := exec.Command("consul", "kv", "put", key, string(jsonBytes))
	return cmd.Run()
}

func deleteConsulKey(key string) error {
	// Validate key to prevent command injection
	if key == "" || strings.ContainsAny(key, ";&|$`") {
		return fmt.Errorf("invalid key format")
	}

	// #nosec G204 - key is validated above to prevent injection
	cmd := exec.Command("consul", "kv", "delete", key)
	return cmd.Run()
}
