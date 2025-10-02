// examples_test.go
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: an AGLIra library
// SPDX-License-Identifier: MPL-2.0

package consul

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExamples_Integration verifies that the integration example runs successfully
func TestExamples_Integration(t *testing.T) {
	// Find the example path
	examplePath := filepath.Join("examples", "integration-demo")

	// Check that the file exists
	mainFile := filepath.Join(examplePath, "main.go")
	if _, err := os.Stat(mainFile); os.IsNotExist(err) {
		t.Skipf("Integration example not found at %s", mainFile)
	}

	// run the example with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "main.go")
	cmd.Dir = examplePath

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Integration example failed: %v\nOutput: %s", err, string(output))
	}

	outputStr := string(output)

	// Check that the output contains the expected success messages
	expectedMessages := []string{
		"Consul provider registered",
		"Provider Discovery",
		"URL Validation",
		"Configuration Loading",
		"Health Checks",
		"Configuration Watching",
		"All integration tests passed!",
	}

	for _, expected := range expectedMessages {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("Expected message not found in output: %s", expected)
		}
	}

	// Check that there are no errors
	if strings.Contains(outputStr, "FAIL") || strings.Contains(outputStr, "Error") {
		t.Errorf("Integration example output contains errors: %s", outputStr)
	}

	t.Logf("✓ Integration example completed successfully")
}

// TestExamples_LiveWatch verifies the live watch example with real Consul (if available)
func TestExamples_LiveWatch(t *testing.T) {
	// Check if CONSUL_ADDR is set for tests with real Consul
	consulAddr := os.Getenv("CONSUL_ADDR")
	if consulAddr == "" {
		t.Skip("Skipping live watch test - set CONSUL_ADDR to enable")
	}

	// Check that Consul is accessible
	if !isConsulAvailable(consulAddr) {
		t.Skipf("Consul not available at %s", consulAddr)
	}

	// Find the example path
	examplePath := filepath.Join("examples", "live-watch-test")

	// Check that the file exists
	mainFile := filepath.Join(examplePath, "main.go")
	if _, err := os.Stat(mainFile); os.IsNotExist(err) {
		t.Skipf("Live watch example not found at %s", mainFile)
	}

	// Run the example with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "main.go")
	cmd.Dir = examplePath
	cmd.Env = append(os.Environ(), fmt.Sprintf("CONSUL_ADDR=%s", consulAddr))

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// The example should complete within the timeout
	if err != nil && !strings.Contains(err.Error(), "signal: killed") {
		t.Fatalf("Live watch example failed: %v\nOutput: %s", err, outputStr)
	}

	// Check that the output contains the expected success messages
	expectedMessages := []string{
		"Live Consul Watch Test",
		"Set initial configuration in Consul",
		"Started watching",
		"CHANGE #1 DETECTED",
		"Real-time watching: VERIFIED",
		"Consul blocking queries: WORKING",
	}

	for _, expected := range expectedMessages {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("Expected message not found in live watch output: %s", expected)
		}
	}

	// Check that multiple changes were detected
	changeCount := strings.Count(outputStr, "CHANGE #")
	if changeCount < 2 {
		t.Errorf("Expected at least 2 configuration changes, got %d", changeCount)
	}

	t.Logf("✓ Live watch example completed successfully with %d configuration changes", changeCount)
}

// TestExamples_Compilation verifies that all examples compile correctly
func TestExamples_Compilation(t *testing.T) {
	examples := []string{
		"examples/integration-demo",
		"examples/live-watch-test",
	}

	for _, examplePath := range examples {
		t.Run(filepath.Base(examplePath), func(t *testing.T) {
			// verify that the example directory exists
			if _, err := os.Stat(examplePath); os.IsNotExist(err) {
				t.Skipf("Example directory not found: %s", examplePath)
			}

			// Compile the example
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, "go", "build", "-v", ".")
			cmd.Dir = examplePath

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to compile example %s: %v\nOutput: %s", examplePath, err, string(output))
			}

			t.Logf("✓ Example %s compiles successfully", examplePath)

			// Cleanup the built binary
			binaryName := filepath.Base(examplePath)
			if strings.Contains(string(output), binaryName) {
				_ = os.Remove(filepath.Join(examplePath, binaryName))
			}
		})
	}
}

// isConsulAvailable verifies that Consul is available at the specified address
func isConsulAvailable(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use curl to check if Consul is responding
	cmd := exec.CommandContext(ctx, "curl", "-s", fmt.Sprintf("http://%s/v1/status/leader", addr))
	err := cmd.Run()
	return err == nil
}

// TestExamples_Documentation verifys that examples contain adequate documentation
func TestExamples_Documentation(t *testing.T) {
	examples := map[string][]string{
		"examples/integration-demo/main.go": {
			"demonstrates real integration with Argus",
			"MockArgusRegistry",
			"RemoteConfigProvider",
		},
		"examples/live-watch-test/main.go": {
			"demonstrates real-time watching capability",
			"TestLiveWatching",
			"configuration changes",
		},
	}

	for filePath, expectedContent := range examples {
		t.Run(filePath, func(t *testing.T) {
			content, err := os.ReadFile(filePath)
			if err != nil {
				t.Skipf("Example file not found: %s", filePath)
			}

			fileContent := string(content)

			for _, expected := range expectedContent {
				if !strings.Contains(strings.ToLower(fileContent), strings.ToLower(expected)) {
					t.Errorf("Expected documentation content not found in %s: %s", filePath, expected)
				}
			}

			// Check that there are appropriate comments
			commentLines := 0
			lines := strings.Split(fileContent, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
					commentLines++
				}
			}

			if commentLines < 10 {
				t.Errorf("Example %s should have more documentation comments (found %d)", filePath, commentLines)
			}

			t.Logf("✓ Example %s has adequate documentation (%d comment lines)", filePath, commentLines)
		})
	}
}
