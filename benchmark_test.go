// benchmark_test.go
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

// BenchmarkValidateSecureKeyPath tests performance of path validation
func BenchmarkValidateSecureKeyPath(b *testing.B) {
	testPaths := []string{
		"config/production/service",
		"config/development/api/settings",
		"services/web/production/config",
		"infrastructure/database/config",
		"monitoring/prometheus/config",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		path := testPaths[i%len(testPaths)]
		_, err := validateSecureKeyPath(path)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// BenchmarkNormalizeHost tests performance of host normalization
func BenchmarkNormalizeHost(b *testing.B) {
	provider := &ConsulProvider{}
	testHosts := []string{
		"localhost",
		"consul.example.com",
		"192.168.1.100",
		"::1",
		"2001:db8::1",
		"consul-server:8501",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		host := testHosts[i%len(testHosts)]
		_ = provider.normalizeHost(host)
	}
}

// BenchmarkParseConsulURL tests performance of URL parsing
func BenchmarkParseConsulURL(b *testing.B) {
	provider := &ConsulProvider{}
	testURLs := []string{
		"consul://localhost:8500/config/myapp",
		"consul://user:pass@consul.example.com:8500/config/production",
		"consul://consul.service.consul:8500/service/api?datacenter=dc1",
		"consul://secure.consul.internal:8500/config/prod?datacenter=dc1&token=ABC123&tls=true",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		url := testURLs[i%len(testURLs)]
		_, _, _, _, err := provider.parseConsulURL(url)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// BenchmarkLoadMock tests performance of Load operation with mock data
func BenchmarkLoadMock(b *testing.B) {
	provider := &ConsulProvider{}

	// Setup mock data
	mockData := map[string]string{
		"config/benchmark": `{"service_name":"benchmark-service","port":8080,"debug":false,"features":["auth","cache","monitoring"],"database":{"host":"db.example.com","port":5432,"pool_size":10}}`,
	}
	provider.SetMockData(mockData)

	ctx := context.Background()
	url := "consul://localhost:8500/config/benchmark"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := provider.Load(ctx, url)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// BenchmarkWatchMockStartup tests performance of Watch startup
func BenchmarkWatchMockStartup(b *testing.B) {
	url := "consul://localhost:8500/config/watch-benchmark"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create fresh provider for each iteration to avoid watch limits
		provider := &ConsulProvider{}

		// Setup mock data
		mockData := map[string]string{
			"config/watch-benchmark": `{"service":"watch-test","enabled":true}`,
		}
		provider.SetMockData(mockData)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)

		configChan, err := provider.Watch(ctx, url)
		if err != nil {
			cancel()
			b.Fatalf("Unexpected error: %v", err)
		}

		// Consume initial config
		select {
		case <-configChan:
		case <-time.After(50 * time.Millisecond):
			// Timeout is acceptable for benchmark
		}

		cancel()
		// Explicitly close provider to cleanup resources
		provider.Close()
	}
}

// BenchmarkCheckDangerousPatterns tests performance of security validation
func BenchmarkCheckDangerousPatterns(b *testing.B) {
	testPaths := []string{
		"config/production/service/settings",
		"services/web/api/configuration",
		"infrastructure/monitoring/prometheus",
		"applications/frontend/build/config",
		"databases/postgresql/cluster/settings",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		path := testPaths[i%len(testPaths)]
		err := checkDangerousPatterns(path)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// BenchmarkCheckWindowsDeviceNames tests performance of Windows device validation
func BenchmarkCheckWindowsDeviceNames(b *testing.B) {
	testPaths := []string{
		"config/production/service/settings",
		"services/web/api/configuration",
		"infrastructure/monitoring/prometheus",
		"applications/frontend/build/config",
		"databases/postgresql/cluster/settings",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		path := testPaths[i%len(testPaths)]
		err := checkWindowsDeviceNames(path)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// BenchmarkGenerateSecureJitter tests performance of jitter generation
func BenchmarkGenerateSecureJitter(b *testing.B) {
	baseDelay := 1 * time.Second

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = generateSecureJitter(baseDelay)
	}
}

// BenchmarkCalculateBackoffDelay tests performance of backoff calculation
func BenchmarkCalculateBackoffDelay(b *testing.B) {
	provider := &ConsulProvider{}
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		attempt := i % 10 // Cycle through different attempt numbers
		_ = provider.calculateBackoffDelay(attempt, baseDelay, maxDelay)
	}
}

// BenchmarkGetSecureCipherSuites tests performance of cipher suite retrieval
func BenchmarkGetSecureCipherSuites(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = getSecureCipherSuites()
	}
}

// BenchmarkExtractHostname tests performance of hostname extraction
func BenchmarkExtractHostname(b *testing.B) {
	testHosts := []string{
		"example.com:8500",
		"192.168.1.100:8501",
		"[::1]:8500",
		"[2001:db8::1]:8501",
		"consul.service.consul:8500",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		host := testHosts[i%len(testHosts)]
		_ = extractHostname(host)
	}
}
