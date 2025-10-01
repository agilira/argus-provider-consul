# Integration Demo Example

This example demonstrates how to integrate the Consul provider with Argus in a real application, simulating typical architecture and usage patterns.

## What It Demonstrates

- ✅ **Provider Registration**: How to register the Consul provider with Argus
- ✅ **Provider Discovery**: How Argus finds and uses registered providers
- ✅ **URL Validation**: Verification of Consul URL syntax and format
- ✅ **Configuration Loading**: Loading JSON configurations from Consul KV
- ✅ **Health Checks**: Monitoring connection and service health status
- ✅ **Real-time Monitoring**: Watching for live configuration updates

## How to Run

### Method 1: Mock Mode (No Consul Required)

```bash
cd examples/integration-demo
go run main.go
```

This example works without a real Consul instance by using internal mock data.

### Method 2: With Real Consul (Optional)

If you have Consul installed and want to test with a real instance:

```bash
# Terminal 1: Start Consul in development mode
consul agent -dev -ui

# Terminal 2: Run the example
cd examples/integration-demo
CONSUL_ADDR=localhost:8500 go run main.go
```

## Expected Output

```
=== Argus-Consul Provider Integration Test ===
✓ Consul provider registered: Consul Remote Configuration Provider v1.0
✓ Handles scheme: consul

--- Test 1: Provider Discovery ---
✓ Found provider: Consul Remote Configuration Provider v1.0

--- Test 2: URL Validation ---
✓ Valid URL: consul://localhost:8500/config/app
✓ Valid URL: consul://user:pass@consul.example.com:8500/service/prod?datacenter=dc1&token=secret
✓ Valid URL: consul://localhost:8500/config/test?tls=true

--- Test 3: Configuration Loading ---
✓ Mock data configured
✓ Loaded Database Config: 5 keys
  - host: localhost
  - port: 5432
  - database: myapp
  - ssl: true
  - pool_size: 10

✓ Loaded Cache Config: 3 keys
  - redis_url: redis://localhost:6379
  - ttl: 3600
  - max_connections: 100

✓ Loaded Service Config: 4 keys
  - log_level: info
  - debug: false
  - metrics_enabled: true
  - version: v1.2.3

--- Test 4: Health Checks ---
✓ Health check passed: Database Config
✓ Health check passed: Cache Config
✓ Health check passed: Service Config

--- Test 5: Configuration Watching ---
✓ Started watching: consul://localhost:8500/config/database
✓ Received config update #1: 5 keys
✓ Watch completed (timeout/cancellation)

=== Integration Test Results ===
✓ Provider registration: SUCCESS
✓ URL validation: SUCCESS
✓ Configuration loading: SUCCESS
✓ Health checks: SUCCESS
✓ Configuration watching: SUCCESS

All integration tests passed!
The Consul provider is ready for production use with Argus.
```

## Code Structure

The example is organized into clear sections:

1. **MockArgusRegistry**: Simulates Argus registry for provider registration
2. **Discovery Tests**: Verifies that the provider is registered correctly
3. **Validation Tests**: Checks various Consul URL formats
4. **Loading Tests**: Loads configurations from specific keys
5. **Health Check Tests**: Verifies connectivity and provider status
6. **Watching Tests**: Demonstrates real-time monitoring

## Test Configurations

The example uses these mock configurations:

```json
// config/database
{
  "host": "localhost",
  "port": 5432,
  "database": "myapp", 
  "ssl": true,
  "pool_size": 10
}

// config/cache
{
  "redis_url": "redis://localhost:6379",
  "ttl": 3600,
  "max_connections": 100
}

// service/production/config  
{
  "log_level": "info",
  "debug": false,
  "metrics_enabled": true,
  "version": "v1.2.3"
}
```

## Production Usage

To use this pattern in your application:

1. **Replace MockArgusRegistry** with the real Argus registry
2. **Configure Consul keys** with your actual configurations
3. **Implement logic** to apply loaded configurations
4. **Handle errors** appropriately for your environment

## Automated Tests

Run automated tests for this example:

```bash
# From project root
go test -run "TestExamples_Integration" -v

# Compilation test
go test -run "TestExamples_Compilation/integration-demo" -v
```

## Troubleshooting

### "Provider registration failed"
- Verify that the Consul provider is imported correctly
- Check that there are no conflicts with other registered providers

### "URL validation failed"  
- Verify the Consul URL syntax
- Check that the scheme is 'consul://'
- Ensure that the path is not empty

### "Configuration loading failed"
- If using real Consul, verify that the keys exist
- Check that values are valid JSON
- Verify connectivity to Consul

## Links

- [Live Watch Example](../live-watch-test/README.md) - Real-time monitoring example
- [Argus Documentation](https://github.com/agilira/argus) - Main Argus documentation
- [Consul Documentation](https://developer.hashicorp.com/consul) - Official Consul documentation