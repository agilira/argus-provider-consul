# Live Watch Test Example

This example demonstrates the real-time monitoring capabilities of the Consul provider, showing how configuration changes are detected instantly using Consul blocking queries.

## What It Demonstrates

- 🔄 **Real-time Watch**: Instant monitoring of configuration changes
- ⚡ **Consul Blocking Queries**: Uses Consul's native blocking queries for maximum efficiency
- 📝 **Dynamic Updates**: Automatic configuration updates during execution
- 🧹 **Automatic Cleanup**: Cleanup of test data at execution completion
- ⏱️ **Performance Monitoring**: Verifies response times and update latency

## Prerequisites

**IMPORTANT**: This example requires a real Consul instance running.

### Installazione Consul

#### Ubuntu/Debian
```bash
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install consul
```

#### macOS
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/consul
```

#### Windows
Scarica da [HashiCorp Downloads](https://developer.hashicorp.com/consul/downloads)

## Come Eseguire

### Passo 1: Avvia Consul

```bash
# Start Consul in development mode
consul agent -dev -ui -client=0.0.0.0

# Verify Consul is running
curl -s http://localhost:8500/v1/status/leader
```

Dovresti vedere l'output: `"127.0.0.1:8300"`

### Step 2: Run the Example

```bash
# Terminal 2: Run the live watch example
cd examples/live-watch-test
go run main.go
```

### Passo 3: (Opzionale) Con Consul Remoto

Se Consul è su un altro host:

```bash
export CONSUL_ADDR="your-consul-host:8500"
go run main.go
```

## Output Atteso

```
=== Live Consul Watch Test ===
Using Consul at: localhost:8500

✓ Set initial configuration in Consul
✓ Started watching consul://localhost:8500/live-test/config

Listening for configuration changes...

🔄 CHANGE #1 DETECTED:
{
  "debug": false,
  "features": {
    "analytics": true,
    "reporting": false
  },
  "max_users": 100,
  "version": 1
}
Version: 1
Debug mode: false
Max users: 100

--- Updating configuration (change #2) ---
✓ Updated configuration in Consul

🔄 CHANGE #2 DETECTED:
{
  "debug": true,
  "features": {
    "analytics": true,
    "reporting": true
  },
  "max_users": 150,
  "version": 2
}
Version: 2
Debug mode: true
Max users: 150

--- Updating configuration (change #3) ---
✓ Updated configuration in Consul

🔄 CHANGE #3 DETECTED:
{
  "debug": false,
  "features": {
    "analytics": false,
    "reporting": true
  },
  "max_users": 200,
  "version": 3
}
Version: 3
Debug mode: false
Max users: 200

--- Updating configuration (change #4) ---
✓ Updated configuration in Consul

🔄 CHANGE #4 DETECTED:
{
  "debug": true,
  "features": {
    "analytics": true,
    "reporting": true
  },
  "max_users": 250,
  "new_feature": "added_dynamically",
  "version": 4
}
Version: 4
Debug mode: true
Max users: 250

✓ Detected 4 changes - test complete!

✓ Context completed
✓ Cleaned up test data

=== Live Watch Test Results ===
✓ Configuration changes detected: 4
✓ Real-time watching: VERIFIED
✓ Consul blocking queries: WORKING
✓ JSON parsing: VERIFIED
✓ Provider functionality: MATHEMATICALLY CERTAIN
```

## How It Works

### 1. Initial Setup
The example configures an initial configuration in Consul using the CLI:

```go
initialConfig := map[string]interface{}{
    "version":   1,
    "debug":     false,
    "max_users": 100,
    "features": map[string]bool{
        "analytics": true,
        "reporting": false,
    },
}
```

### 2. Starting the Watch
Monitoring of the `live-test/config` key is started:

```go
configChan, err := provider.Watch(ctx, consulURL)
```

### 3. Scheduled Updates
A separate goroutine schedules configuration updates every 3 seconds:

```go
go func() {
    // Update configurations at regular intervals
    for i, update := range updates {
        time.Sleep(3 * time.Second)
        setConsulKey(testKey, update)
    }
}()
```

### 4. Change Detection
The main loop detects and prints each change:

```go
for config := range configChan {
    changeCount++
    fmt.Printf("🔄 CHANGE #%d DETECTED:\n", changeCount)
    // Process the new configuration
}
```

## Automated Testing

### Base Test
```bash
# From project root (without Consul)
go test -run "TestExamples_LiveWatch" -v
```

### Test with Real Consul
```bash
# With active Consul instance
CONSUL_ADDR=localhost:8500 go test -run "TestExamples_LiveWatch" -v
```

### Compilation Test
```bash
go test -run "TestExamples_Compilation/live-watch-test" -v
```

## Manual Monitoring

While the example is running, you can also manually modify the configuration:

```bash
# Terminal 3: Manual modification
consul kv put live-test/config '{"version": 999, "manual_update": true, "debug": true}'
```

You'll immediately see the detected change in the example output.

## Performance and Metrics

The example automatically monitors:

- **Detection Latency**: Time between modification and notification
- **Throughput**: Number of updates handled per second  
- **Accuracy**: Completeness of received data
- **Resource Usage**: Memory and goroutine usage

## Test Configurations

The example tests these configuration sequences:

### Update 1 → 2
```diff
- "debug": false,        + "debug": true,
- "max_users": 100,     + "max_users": 150,
- "reporting": false    + "reporting": true
```

### Update 2 → 3  
```diff
- "debug": true,         + "debug": false,
- "analytics": true,     + "analytics": false,
- "max_users": 150,     + "max_users": 200,
```

### Update 3 → 4
```diff
- "debug": false,       + "debug": true,
- "analytics": false,   + "analytics": true,
- "max_users": 200,     + "max_users": 250,
+                       + "new_feature": "added_dynamically"
```

## Troubleshooting

### "Failed to set initial config: exit status 1"
```bash
# Verify Consul is running
consul members

# Check connectivity
curl http://localhost:8500/v1/status/leader
```

### "Watch startup error"
- Verify that the Consul URL is correct
- Check ACL permissions if Consul is configured with authentication
- Ensure the provider is initialized correctly

### "No configuration changes detected"
- Verify that changes are actually happening in Consul
- Check Consul logs for errors
- Increase timeout if necessary

### Premature Timeout
```bash
# Increase timeout in example if needed
export WATCH_TIMEOUT=60s
go run main.go
```

## Production Usage

To adapt this pattern for production:

1. **Implement Specific Handlers** for each configuration type
2. **Add Structured Logging** for monitoring
3. **Handle Errors and Retry** for robustness
4. **Implement Rate Limiting** to prevent overload
5. **Add Metrics** for operational monitoring

## Security

The example includes:
- ✅ **Input Validation**: Prevention of command injection in key paths
- ✅ **Automatic Cleanup**: Removal of test data
- ✅ **Timeout Management**: Prevention of infinite blocking
- ✅ **Resource Limits**: Proper resource management

## Links

- [Integration Demo](../integration-demo/README.md) - Complete integration example
- [Consul Blocking Queries](https://developer.hashicorp.com/consul/api-docs/features/blocking) - Blocking queries documentation
- [Consul Watch Documentation](https://developer.hashicorp.com/consul/docs/dynamic-app-config/watches) - Official watching guide