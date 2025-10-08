# argus-provider-consul: Argus remote provider for HashiCorp Consul
### an AGILira library

Official [Argus](https://github.com/agilira/argus) provider for remote configuration management through [HashiCorp Consul](https://github.com/hashicorp/consul).
It enables real-time configuration loading and watching from Consul KV store with native blocking queries, multi-datacenter support, and production-ready security features.

[![CI](https://github.com/agilira/argus-provider-consul/actions/workflows/ci.yml/badge.svg)](https://github.com/agilira/argus-provider-consul/actions/workflows/ci.yml)
[![CodeQL](https://github.com/agilira/argus-provider-consul/actions/workflows/codeql.yml/badge.svg)](https://github.com/agilira/argus-provider-consul/actions/workflows/codeql.yml)
[![Security](https://img.shields.io/badge/Security-gosec-brightgreen)](https://github.com/agilira/argus-provider-consul/actions/workflows/ci.yml)
[![Go Report Card](https://img.shields.io/badge/go_report-A+-brightgreen)](https://goreportcard.com/report/github.com/agilira/argus-provider-consul)
[![Made For Argus](https://img.shields.io/badge/Made_for-Argus-AFEEEE)](https://github.com/agilira/argus)

**[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Configuration](#configuration) • [Demo](#demo) • [Requirements](#requirements)**

## Features

- **Real-time Native Watch**: Leverages Consul blocking queries for instant updates with minimal overhead.
- **Multi-Datacenter Support**: Specify the desired datacenter directly in the configuration URL.
- **ACL Token Authentication**: Secure integration with protected Consul environments.
- **TLS Connections**: Support for encrypted communication with the Consul cluster.
- **Secure by Design**: Red-team tested against path traversal, SSRF, resource exhaustion & TLS bypass attacks.
- **Resource Protection**: Built-in limits for concurrent connections, memory usage, and goroutine management.
- **Integrated Health Check**: Verifies connectivity and Consul cluster status.

## Compatibility and Support

argus-provider-consul is designed to work with Consul 1.32+ and follows Long-Term Support guidelines to ensure consistent performance across production deployments.

## Installation

```bash

go get github.com/agilira/argus-provider-consul

```

## Quick Start

To use the provider, import it and register it with Argus:

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/agilira/argus" // Argus core
    consul "github.com/agilira/argus-provider-consul" // Consul provider
)

func main() {
    // Register the Consul provider
    consulProvider, err := consul.GetProvider()
    if err != nil {
        log.Fatal("Failed to create Consul provider:", err)
    }
    
    if err := argus.RegisterRemoteProvider("consul", consulProvider); err != nil {
        log.Fatal("Failed to register Consul provider:", err)
    }

    consulURL := "consul://localhost:8500/config/myapp"

    // --- Single Load ---
    log.Println("Loading configuration from Consul...")
    config, err := argus.LoadRemoteConfig(consulURL)
    if err != nil {
        log.Fatalf("Configuration loading error: %v", err)
    }
    log.Printf("Configuration loaded: %+v\n", config)


    // --- Real-time Monitoring ---
    log.Println("\nStarting real-time monitoring (watch)...")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    configChan, err := argus.WatchRemoteConfigWithContext(ctx, consulURL)
    if err != nil {
        log.Fatalf("Watch startup error: %v", err)
    }

    // Goroutine to handle updates
    go func() {
        for newConfig := range configChan {
            log.Printf("Configuration update received: %+v\n", newConfig)
            // Apply new configuration to your application here
        }
        log.Println("Watch channel closed.")
    }()

    // Keep application running to receive updates
    <-ctx.Done()
}

```

## Configuration

### URL Format

The provider is configured through a specific URL:

```
consul://[user:pass@]host:port/key/path[?query_params]
```

**Components:**

- **host:port**: Your Consul agent address (default: localhost:8500)
- **key/path**: Complete path in Consul's K/V store where configuration is stored
- **query_params** (optional):
  - `datacenter=dc1`: Specify a different Consul datacenter
  - `token=SECRET_TOKEN`: Provide ACL token for authentication
  - `tls=true`: Enable HTTPS communication

### Examples

```go
// Basic configuration
"consul://localhost:8500/services/my-app/config"

// Multi-datacenter with authentication
"consul://consul.my-domain.com/production/database/config?datacenter=us-east-1&token=a1b2-c3d4"

// Secure connection
"consul://127.0.0.1:8500/features/flags?tls=true"
```

### Storing Configuration in Consul

The provider expects the value associated with the key in Consul to be a JSON string.

**Example with Consul CLI:**

```bash
consul kv put config/myapp '{
  "service_name": "my-awesome-app",
  "port": 8080,
  "debug": true,
  "features": {
    "enable_feature_x": true
  }
}'
```

## Demo

- **[Examples](./examples/)** - Working examples and demos

## Requirements

- Go 1.24+
- HashiCorp Consul
- [github.com/hashicorp/consul/api](https://github.com/hashicorp/consul) v1.32.3+

## License

Mozilla Public License 2.0 - see the [LICENSE](LICENSE.md) file for details.

---

argus-provider-consul • an AGILira library