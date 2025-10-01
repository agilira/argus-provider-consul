// main_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSetConsulKey verifies setConsulKey function with various inputs
func TestSetConsulKey(t *testing.T) {
	// Test successful config marshaling
	t.Run("valid_config_marshaling", func(t *testing.T) {
		config := map[string]interface{}{
			"version":   1,
			"debug":     false,
			"max_users": 100,
			"features": map[string]bool{
				"analytics": true,
				"reporting": false,
			},
		}

		// This will fail without real Consul, but we test the validation logic
		err := setConsulKey("test/valid-key", config)

		// We expect it to fail due to missing Consul, but not due to validation errors
		if err != nil {
			// The error should be about Consul connectivity, not validation
			if strings.Contains(err.Error(), "invalid key format") {
				t.Errorf("Key validation should pass for valid key, got: %v", err)
			}
		}
	})

	// Test key validation security
	t.Run("key_validation_security", func(t *testing.T) {
		config := map[string]interface{}{"test": "value"}

		// Test empty key
		err := setConsulKey("", config)
		if err == nil {
			t.Fatal("Expected error for empty key")
		}
		if !strings.Contains(err.Error(), "invalid key format") {
			t.Errorf("Expected 'invalid key format' error, got: %v", err)
		}

		// Test dangerous characters that could enable command injection
		dangerousKeys := []string{
			"test;rm -rf /",        // Command separator
			"test&whoami",          // Command separator
			"test|cat /etc/passwd", // Pipe
			"test$HOME",            // Variable expansion
			"test`whoami`",         // Command substitution
		}

		for _, key := range dangerousKeys {
			err := setConsulKey(key, config)
			if err == nil {
				t.Errorf("Expected security error for dangerous key: %s", key)
			}
			if !strings.Contains(err.Error(), "invalid key format") {
				t.Errorf("Expected 'invalid key format' error for key '%s', got: %v", key, err)
			}
		}
	})

	// Test valid keys that should pass validation
	t.Run("valid_keys", func(t *testing.T) {
		config := map[string]interface{}{"test": "value"}

		validKeys := []string{
			"test/config",
			"app/database/settings",
			"service-name/config",
			"my_app/feature_flags",
			"config123/test456",
		}

		for _, key := range validKeys {
			err := setConsulKey(key, config)
			// We expect Consul connection errors, but not validation errors
			if err != nil && strings.Contains(err.Error(), "invalid key format") {
				t.Errorf("Key validation should pass for valid key '%s', got: %v", key, err)
			}
		}
	})

	// Test JSON marshaling errors
	t.Run("json_marshaling_errors", func(t *testing.T) {
		// Create a config that can't be marshaled to JSON
		invalidConfig := map[string]interface{}{
			"channel": make(chan int), // Channels can't be marshaled to JSON
		}

		err := setConsulKey("test/config", invalidConfig)
		if err == nil {
			t.Fatal("Expected JSON marshaling error")
		}

		// The error should be about JSON marshaling, not key validation
		if strings.Contains(err.Error(), "invalid key format") {
			t.Error("Should get JSON marshaling error, not key validation error")
		}
	})
}

// TestDeleteConsulKey verifies deleteConsulKey function security
func TestDeleteConsulKey(t *testing.T) {
	// Test key validation security in delete function
	t.Run("key_validation_security", func(t *testing.T) {
		// Test empty key
		err := deleteConsulKey("")
		if err == nil {
			t.Fatal("Expected error for empty key")
		}
		if !strings.Contains(err.Error(), "invalid key format") {
			t.Errorf("Expected 'invalid key format' error, got: %v", err)
		}

		// Test dangerous characters
		dangerousKeys := []string{
			"test;rm -rf /",
			"test&whoami",
			"test|cat /etc/passwd",
			"test$HOME",
			"test`whoami`",
		}

		for _, key := range dangerousKeys {
			err := deleteConsulKey(key)
			if err == nil {
				t.Errorf("Expected security error for dangerous key: %s", key)
			}
			if !strings.Contains(err.Error(), "invalid key format") {
				t.Errorf("Expected 'invalid key format' error for key '%s', got: %v", key, err)
			}
		}
	})

	// Test valid keys
	t.Run("valid_keys", func(t *testing.T) {
		validKeys := []string{
			"test/config",
			"app/database/settings",
			"service-name/config",
			"my_app/feature_flags",
		}

		for _, key := range validKeys {
			err := deleteConsulKey(key)
			// We expect Consul connection errors, but not validation errors
			if err != nil && strings.Contains(err.Error(), "invalid key format") {
				t.Errorf("Key validation should pass for valid key '%s', got: %v", key, err)
			}
		}
	})
}

// TestConfigurationStructures verifies that test configurations are valid JSON
func TestConfigurationStructures(t *testing.T) {
	// Test initial configuration structure
	t.Run("initial_config", func(t *testing.T) {
		initialConfig := map[string]interface{}{
			"version":   1,
			"debug":     false,
			"max_users": 100,
			"features": map[string]bool{
				"analytics": true,
				"reporting": false,
			},
		}

		// Verify it can be marshaled to JSON
		jsonBytes, err := json.Marshal(initialConfig)
		if err != nil {
			t.Fatalf("Failed to marshal initial config to JSON: %v", err)
		}

		// Verify it can be unmarshaled back
		var restored map[string]interface{}
		err = json.Unmarshal(jsonBytes, &restored)
		if err != nil {
			t.Fatalf("Failed to unmarshal initial config from JSON: %v", err)
		}

		// Verify key fields exist
		if restored["version"] != float64(1) {
			t.Errorf("Expected version 1, got %v", restored["version"])
		}
		if restored["debug"] != false {
			t.Errorf("Expected debug false, got %v", restored["debug"])
		}
		if restored["max_users"] != float64(100) {
			t.Errorf("Expected max_users 100, got %v", restored["max_users"])
		}
	})

	// Test update configurations
	t.Run("update_configs", func(t *testing.T) {
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
			t.Run(func() string { return "update_" + string(rune(i+1+'0')) }(), func(t *testing.T) {
				// Verify it can be marshaled to JSON
				jsonBytes, err := json.Marshal(update)
				if err != nil {
					t.Fatalf("Failed to marshal update config %d to JSON: %v", i+1, err)
				}

				// Verify it can be unmarshaled back
				var restored map[string]interface{}
				err = json.Unmarshal(jsonBytes, &restored)
				if err != nil {
					t.Fatalf("Failed to unmarshal update config %d from JSON: %v", i+1, err)
				}

				// Verify version increments correctly
				expectedVersion := float64(i + 2)
				if restored["version"] != expectedVersion {
					t.Errorf("Expected version %v, got %v", expectedVersion, restored["version"])
				}

				// Verify features structure
				if features, ok := restored["features"].(map[string]interface{}); ok {
					if _, hasAnalytics := features["analytics"]; !hasAnalytics {
						t.Error("Expected 'analytics' feature in features map")
					}
					if _, hasReporting := features["reporting"]; !hasReporting {
						t.Error("Expected 'reporting' feature in features map")
					}
				} else {
					t.Error("Expected 'features' to be a map")
				}
			})
		}
	})
}

// TestKeyValidationRules verifies the security rules for key validation
func TestKeyValidationRules(t *testing.T) {
	testCases := []struct {
		key   string
		valid bool
		name  string
	}{
		{"", false, "empty_key"},
		{"valid/path", true, "simple_path"},
		{"app/config/database", true, "nested_path"},
		{"service-name/config", true, "hyphenated_name"},
		{"my_app/settings", true, "underscore_name"},
		{"config123/test456", true, "numeric_suffix"},
		{"test;rm", false, "semicolon_injection"},
		{"test&whoami", false, "ampersand_injection"},
		{"test|cat", false, "pipe_injection"},
		{"test$HOME", false, "variable_injection"},
		{"test`whoami`", false, "backtick_injection"},
		{"test$(whoami)", false, "dollar_paren_injection"},
		{"test;ls;", false, "multiple_semicolons"},
		{"normal/path/test", true, "normal_nested_path"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test both setConsulKey and deleteConsulKey validation
			config := map[string]interface{}{"test": "value"}

			setErr := setConsulKey(tc.key, config)
			deleteErr := deleteConsulKey(tc.key)

			if tc.valid {
				// For valid keys, we should not get validation errors
				// (We may get Consul connection errors, but that's different)
				if setErr != nil && strings.Contains(setErr.Error(), "invalid key format") {
					t.Errorf("setConsulKey: Expected valid key '%s' to pass validation, got: %v", tc.key, setErr)
				}
				if deleteErr != nil && strings.Contains(deleteErr.Error(), "invalid key format") {
					t.Errorf("deleteConsulKey: Expected valid key '%s' to pass validation, got: %v", tc.key, deleteErr)
				}
			} else {
				// For invalid keys, we should get validation errors
				if setErr == nil || !strings.Contains(setErr.Error(), "invalid key format") {
					t.Errorf("setConsulKey: Expected invalid key '%s' to fail validation, got: %v", tc.key, setErr)
				}
				if deleteErr == nil || !strings.Contains(deleteErr.Error(), "invalid key format") {
					t.Errorf("deleteConsulKey: Expected invalid key '%s' to fail validation, got: %v", tc.key, deleteErr)
				}
			}
		})
	}
}

// TestMainFunctionComponents verifies components used in main function
func TestMainFunctionComponents(t *testing.T) {
	// Test that we can create the configurations used in main
	t.Run("main_config_creation", func(t *testing.T) {
		// Test creating the initial config like in main()
		initialConfig := map[string]interface{}{
			"version":   1,
			"debug":     false,
			"max_users": 100,
			"features": map[string]bool{
				"analytics": true,
				"reporting": false,
			},
		}

		// Verify we can marshal it (this is what setConsulKey does internally)
		_, err := json.Marshal(initialConfig)
		if err != nil {
			t.Fatalf("Failed to marshal main's initial config: %v", err)
		}

		t.Log("✓ Main function's initial config structure is valid")
	})

	// Test the update sequence used in main
	t.Run("main_update_sequence", func(t *testing.T) {
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

		// Verify all updates can be marshaled
		for i, update := range updates {
			_, err := json.Marshal(update)
			if err != nil {
				t.Fatalf("Failed to marshal update %d: %v", i+1, err)
			}
		}

		t.Logf("✓ All %d update configurations are valid", len(updates))
	})
}

// BenchmarkKeyValidation benchmarks the key validation performance
func BenchmarkKeyValidation(b *testing.B) {
	config := map[string]interface{}{"benchmark": true}

	b.Run("ValidKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = setConsulKey("benchmark/valid/key", config)
		}
	})

	b.Run("InvalidKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = setConsulKey("benchmark;invalid", config)
		}
	})
}

// BenchmarkJSONMarshaling benchmarks JSON marshaling performance
func BenchmarkJSONMarshaling(b *testing.B) {
	config := map[string]interface{}{
		"version":   1,
		"debug":     false,
		"max_users": 100,
		"features": map[string]bool{
			"analytics": true,
			"reporting": false,
		},
		"nested": map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": "deep_value",
				"array":  []int{1, 2, 3, 4, 5},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(config)
	}
}
