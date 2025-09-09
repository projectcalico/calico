# RapidClient

A simple HTTP client tool that forces source port reuse by bypassing TIME_WAIT state, designed for testing Maglev consistent hashing and load balancer behavior.

## Features

- **Source Port Reuse**: Forces connections to use a specific source port, bypassing TIME_WAIT
- **New TCP Connection**: Each call establishes a fresh TCP connection (no connection reuse)
- **Socket Options**: Sets SO_REUSEADDR for rapid port reuse
- **Simple Output**: Sends a single request and prints the raw response
- **Configurable**: Command-line options for URL, source port, and timeout

## Usage

### Docker Run
```bash
# Basic Docker usage with host networking
docker run --rm --network host rapidclient:latest -url "http://10.103.218.83:8080/shell?cmd=hostname"

# With verbose output
docker run --rm --network host rapidclient:latest -url "http://10.103.218.83:8080/shell?cmd=hostname" -v

# With custom source port
docker run --rm --network host rapidclient:latest -url "http://10.103.218.83:8080/shell?cmd=hostname" -port 54321

# With custom timeout
docker run --rm --network host rapidclient:latest -url "http://10.103.218.83:8080/shell?cmd=hostname" -timeout 10s
```

### Basic Usage
```bash
# Send a single request to a service
./rapidclient -url "http://10.96.0.1:8080/shell?cmd=hostname"

# Use a specific source port
./rapidclient -url "http://10.96.0.1:8080/shell?cmd=hostname" -port 12345

# Verbose output with status information
./rapidclient -url "http://10.96.0.1:8080/shell?cmd=hostname" -v
```

### Command Line Options

- `-url string`: Target URL to send request to (required)
- `-port int`: Source port to use for connection (default: 12345)
- `-timeout duration`: Request timeout (default: 30s)
- `-v`: Verbose logging (shows status and debug info)

### Examples

```bash
# Test Maglev load balancing with consistent source port
./rapidclient -url "http://service-ip:8080/shell?cmd=hostname" -port 12345

# Test with custom timeout
./rapidclient -url "http://service-ip:8080/api/health" -timeout 10s

# Verbose mode for debugging
./rapidclient -url "http://service-ip:8080/shell?cmd=hostname" -port 12345 -v
```

## Technical Details

- Uses `SO_REUSEADDR` socket option to allow rapid port reuse
- Disables HTTP keep-alive to force new connections
- Custom dialer with specific source port binding
- Handles both IPv4 and IPv6 connections

## Output

### Normal Mode
```bash
$ ./rapidclient -url "http://10.96.0.1:8080/shell?cmd=hostname"
{"output":"backend-pod-5\n"}
```

### Verbose Mode
```bash
$ ./rapidclient -url "http://10.96.0.1:8080/shell?cmd=hostname" -v
2025/09/04 10:30:00 Sending request to: http://10.96.0.1:8080/shell?cmd=hostname
2025/09/04 10:30:00 Using source port: 12345
2025/09/04 10:30:00 Timeout: 30s
Status: 200 OK
Response: {"output":"backend-pod-5\n"}
```

## Integration with Tests

This tool can replace curl commands in tests for better reliability:

```bash
# Instead of:
curl --local-port 12345 -s http://service:8080/shell?cmd=hostname

# Use:
./rapidclient -url "http://service:8080/shell?cmd=hostname" -port 12345
```
