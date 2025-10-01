// Package consul provides a high-performance HashiCorp Consul remote configuration provider for Argus.
//
// # Overview
//
// This package implements the Argus RemoteConfigProvider interface to enable real-time
// configuration loading and monitoring from HashiCorp Consul Key-Value store. The provider
// leverages Consul's native blocking queries for efficient, near-instantaneous configuration
// updates with minimal network overhead and CPU usage.
//
// The implementation follows high-performance design principles with lock-free operations,
// pre-allocated buffers, connection pooling, and minimal memory allocations during runtime
// operations. It's designed for production environments where every nanosecond matters.
//
// # Key Features
//
//   - Real-time Native Watch: Uses Consul blocking queries for instant updates with minimal overhead
//   - Multi-Datacenter Support: Seamless configuration routing across Consul datacenters
//   - ACL Token Authentication: Secure integration with protected Consul environments
//   - TLS/SSL Connections: Encrypted communication support for secure deployments
//   - Health Monitoring: Comprehensive connectivity and cluster health verification
//   - Connection Pooling: Efficient HTTP connection reuse for optimal performance
//   - Thread-Safe Operations: Concurrent access with atomic operations and sync.Once patterns
//   - Graceful Shutdown: Proper resource cleanup to prevent memory and connection leaks
//
// # URL Format and Configuration
//
// The provider accepts Consul URLs in the following format:
//
//	consul://[username:password@]host:port/key/path[?query_params]
//
// Where query_params can include:
//   - datacenter=dc1: Specify target Consul datacenter
//   - token=SECRET_TOKEN: Provide ACL token for authentication
//   - tls=true: Enable HTTPS communication with Consul
//
// # Examples
//
// Basic configuration loading:
//
//	import (
//	    "context"
//	    "log"
//
//	    "github.com/agilira/argus"
//	    consul "github.com/agilira/argus-provider-consul"
//	)
//
//	func main() {
//	    // Register the Consul provider with Argus
//	    provider, err := consul.GetProvider()
//	    if err != nil {
//	        log.Fatal("Failed to create Consul provider:", err)
//	    }
//
//	    if err := argus.RegisterRemoteProvider("consul", provider); err != nil {
//	        log.Fatal("Failed to register provider:", err)
//	    }
//
//	    // Load configuration from Consul KV store
//	    config, err := argus.LoadRemoteConfig("consul://localhost:8500/config/myapp")
//	    if err != nil {
//	        log.Fatal("Configuration loading failed:", err)
//	    }
//
//	    log.Printf("Configuration loaded: %+v", config)
//	}
//
// Real-time configuration monitoring with native Consul blocking queries:
//
//	func watchConfiguration() {
//	    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	    defer cancel()
//
//	    // Start watching for configuration changes
//	    configChan, err := argus.WatchRemoteConfigWithContext(ctx,
//	        "consul://localhost:8500/config/myapp")
//	    if err != nil {
//	        log.Fatal("Watch startup failed:", err)
//	    }
//
//	    // Handle real-time configuration updates
//	    go func() {
//	        for newConfig := range configChan {
//	            log.Printf("Configuration updated: %+v", newConfig)
//	            // Apply new configuration to your application
//	        }
//	    }()
//
//	    <-ctx.Done()
//	}
//
// Multi-datacenter configuration with authentication:
//
//	consulURL := "consul://consul.example.com:8500/production/database/config?" +
//	    "datacenter=us-east-1&token=a1b2c3d4&tls=true"
//
//	config, err := argus.LoadRemoteConfig(consulURL)
//	if err != nil {
//	    log.Fatal("Multi-DC configuration loading failed:", err)
//	}
//
// # Configuration Storage in Consul
//
// The provider expects configuration values to be stored as JSON in Consul KV store.
// This allows for structured configuration with nested objects and arrays.
//
// Example using Consul CLI:
//
//	consul kv put config/myapp '{
//	  "service_name": "my-service",
//	  "port": 8080,
//	  "database": {
//	    "host": "db.example.com",
//	    "port": 5432,
//	    "ssl": true
//	  },
//	  "features": {
//	    "enable_metrics": true,
//	    "enable_tracing": false
//	  }
//	}'
//
// Example using Consul HTTP API:
//
//	curl -X PUT http://localhost:8500/v1/kv/config/myapp \
//	  -d '{"service_name":"my-service","port":8080}'
//
// # Performance Characteristics
//
// The provider is optimized for high-performance production environments:
//
//   - Lock-Free Design: Uses atomic operations for concurrent access without mutexes
//   - Minimal Allocations: Pre-allocated buffers and object pooling where applicable
//   - Connection Reuse: HTTP connection pooling for reduced network overhead
//   - Efficient Watching: Consul blocking queries provide real-time updates with minimal CPU usage
//   - Memory Efficiency: Careful resource management prevents memory leaks in long-running applications
//
// Benchmarks show negligible overhead for configuration loading and watching operations,
// making it suitable for latency-sensitive applications.
//
// # Security and Authentication
//
// The provider supports multiple authentication methods:
//
//   - HTTP Basic Auth: Username/password in URL (consul://user:pass@host:port/key)
//   - ACL Tokens: Consul native token authentication via query parameter
//   - TLS/SSL: Encrypted communication for secure environments
//   - Datacenter Isolation: Route requests to specific datacenters for security boundaries
//
// Security best practices:
//   - Always use TLS in production environments
//   - Store ACL tokens securely (environment variables, secret management systems)
//   - Use least-privilege ACL policies for configuration access
//   - Implement proper network segmentation for Consul clusters
//
// # Error Handling and Resilience
//
// The provider implements comprehensive error handling with custom error types:
//
//   - ARGUS_INVALID_CONFIG: Malformed URLs or invalid configuration parameters
//   - ARGUS_CONFIG_NOT_FOUND: Requested Consul key does not exist
//   - ARGUS_REMOTE_CONFIG_ERROR: Network, authentication, or parsing errors
//   - ARGUS_PROVIDER_CLOSED: Operations attempted on closed provider instances
//
// Watch operations include exponential backoff with jitter for connection failures,
// ensuring resilient behavior in unstable network conditions.
//
// # Health Monitoring
//
// Built-in health check capabilities verify:
//   - Consul agent connectivity and responsiveness
//   - Cluster leadership and consensus state
//   - Network path availability
//   - Authentication credential validity
//
// Health checks are essential for:
//   - Circuit breaker patterns in microservices
//   - Load balancer health endpoints
//   - Monitoring and alerting systems
//   - Startup validation in containerized environments
//
// # Testing Support
//
// The provider includes comprehensive testing capabilities:
//   - Mock implementation for unit testing without Consul dependencies
//   - Configurable mock data and datacenter simulation
//   - Integration test helpers for full end-to-end testing
//   - Benchmarking tools for performance validation
//
// Example testing setup:
//
//	func TestConfigurationLoading(t *testing.T) {
//	    provider := &ConsulProvider{}
//	    provider.SetMockData(map[string]string{
//	        "config/test": `{"key": "value"}`,
//	    })
//
//	    config, err := provider.Load(context.Background(),
//	        "consul://localhost:8500/config/test")
//	    assert.NoError(t, err)
//	    assert.Equal(t, "value", config["key"])
//	}
//
// # Architecture and Design Patterns
//
// The implementation follows Go best practices and design patterns:
//
//   - Interface Segregation: Clean separation between provider interface and implementation
//   - Dependency Injection: No direct Argus imports to avoid circular dependencies
//   - Factory Pattern: GetProvider() function for clean instantiation
//   - Resource Management: Proper cleanup and resource lifecycle management
//   - Thread Safety: sync.Once and atomic operations for concurrent access
//   - Error Wrapping: Structured error handling with context preservation
//
// The provider is designed as a standalone library that implements the Argus
// RemoteConfigProvider interface without importing Argus itself, preventing
// circular dependency issues and enabling independent testing and development.
//
// # Compatibility and Support
//
// System Requirements:
//   - Go 1.25+ (leverages latest performance improvements)
//   - HashiCorp Consul 1.32+ (requires modern blocking query support)
//   - Linux/macOS/Windows (cross-platform compatibility)
//
// The provider follows Long-Term Support guidelines and maintains backward
// compatibility with stable Consul API versions. Breaking changes are avoided
// and deprecated features receive advance notice through semantic versioning.
//
// # Production Deployment Considerations
//
// For production deployments, consider:
//
//   - Connection Limits: Configure appropriate HTTP client timeouts and connection pools
//   - Network Latency: Place applications close to Consul clusters for optimal performance
//   - Monitoring: Implement metrics collection for configuration load times and error rates
//   - Backup Strategies: Ensure Consul cluster backup and disaster recovery procedures
//   - Security Hardening: Follow Consul security best practices for ACLs and network isolation
//   - Resource Management: Always call Close() on provider instances in long-running applications
//
// # License and Contribution
//
// This package is licensed under the Mozilla Public License 2.0 (MPL-2.0).
// For contribution guidelines, bug reports, and feature requests, visit:
// https://github.com/agilira/argus-provider-consul
//
// Copyright (c) 2025 AGILira - A. Giordano
// Series: AGILira System Libraries
// SPDX-License-Identifier: MPL-2.0
package consul
