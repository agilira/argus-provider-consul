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

// TestExamples_Integration verifica che l'esempio di integrazione funzioni correttamente
func TestExamples_Integration(t *testing.T) {
	// Trova il percorso dell'esempio
	examplePath := filepath.Join("examples", "integration-demo")

	// Verifica che il file esista
	mainFile := filepath.Join(examplePath, "main.go")
	if _, err := os.Stat(mainFile); os.IsNotExist(err) {
		t.Skipf("Integration example not found at %s", mainFile)
	}

	// Esegui l'esempio
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "main.go")
	cmd.Dir = examplePath

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Integration example failed: %v\nOutput: %s", err, string(output))
	}

	outputStr := string(output)

	// Verifica che l'output contenga i messaggi di successo attesi
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

	// Verifica che non ci siano errori
	if strings.Contains(outputStr, "FAIL") || strings.Contains(outputStr, "Error") {
		t.Errorf("Integration example output contains errors: %s", outputStr)
	}

	t.Logf("✓ Integration example completed successfully")
}

// TestExamples_LiveWatch verifica l'esempio di live watch con Consul reale (se disponibile)
func TestExamples_LiveWatch(t *testing.T) {
	// Controlla se CONSUL_ADDR è impostato per i test con Consul reale
	consulAddr := os.Getenv("CONSUL_ADDR")
	if consulAddr == "" {
		t.Skip("Skipping live watch test - set CONSUL_ADDR to enable")
	}

	// Verifica che Consul sia accessibile
	if !isConsulAvailable(consulAddr) {
		t.Skipf("Consul not available at %s", consulAddr)
	}

	// Trova il percorso dell'esempio
	examplePath := filepath.Join("examples", "live-watch-test")

	// Verifica che il file esista
	mainFile := filepath.Join(examplePath, "main.go")
	if _, err := os.Stat(mainFile); os.IsNotExist(err) {
		t.Skipf("Live watch example not found at %s", mainFile)
	}

	// Esegui l'esempio con timeout
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "main.go")
	cmd.Dir = examplePath
	cmd.Env = append(os.Environ(), fmt.Sprintf("CONSUL_ADDR=%s", consulAddr))

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// L'esempio dovrebbe completarsi entro il timeout
	if err != nil && !strings.Contains(err.Error(), "signal: killed") {
		t.Fatalf("Live watch example failed: %v\nOutput: %s", err, outputStr)
	}

	// Verifica che l'output contenga i messaggi di successo attesi
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

	// Verifica che siano state rilevate multiple modifiche
	changeCount := strings.Count(outputStr, "CHANGE #")
	if changeCount < 2 {
		t.Errorf("Expected at least 2 configuration changes, got %d", changeCount)
	}

	t.Logf("✓ Live watch example completed successfully with %d configuration changes", changeCount)
}

// TestExamples_Compilation verifica che tutti gli esempi si compilino correttamente
func TestExamples_Compilation(t *testing.T) {
	examples := []string{
		"examples/integration-demo",
		"examples/live-watch-test",
	}

	for _, examplePath := range examples {
		t.Run(filepath.Base(examplePath), func(t *testing.T) {
			// Verifica che la directory esista
			if _, err := os.Stat(examplePath); os.IsNotExist(err) {
				t.Skipf("Example directory not found: %s", examplePath)
			}

			// Compila l'esempio
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, "go", "build", "-v", ".")
			cmd.Dir = examplePath

			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to compile example %s: %v\nOutput: %s", examplePath, err, string(output))
			}

			t.Logf("✓ Example %s compiles successfully", examplePath)

			// Pulisci il binario creato
			binaryName := filepath.Base(examplePath)
			if strings.Contains(string(output), binaryName) {
				_ = os.Remove(filepath.Join(examplePath, binaryName))
			}
		})
	}
}

// isConsulAvailable verifica se Consul è disponibile all'indirizzo specificato
func isConsulAvailable(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Usa curl per verificare se Consul risponde
	cmd := exec.CommandContext(ctx, "curl", "-s", fmt.Sprintf("http://%s/v1/status/leader", addr))
	err := cmd.Run()
	return err == nil
}

// TestExamples_Documentation verifica che la documentazione degli esempi sia presente
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

			// Verifica che ci siano commenti appropriati
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
