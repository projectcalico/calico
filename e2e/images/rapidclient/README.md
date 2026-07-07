# rapidclient

A multi-mode e2e test utility image. The mode is selected by the `MODE`
environment variable; an unset `MODE` defaults to `client` (the original
behaviour). See [DESIGN.md](DESIGN.md) for the full contract and rationale.

## Modes

| `MODE` | Purpose |
|---|---|
| `client` (default) | HTTP client that forces source-port reuse — for Maglev / load-balancer tests. Configured via flags (below). |
| `server` | HTTP + UDP "dataplane server" for packet-size tests (ports the former `k8s-e2e-dataplane-server` flask image). Configured via the `PORT` env (default 5000). |

### `server` mode

Listens for TCP HTTP and UDP echo on the same port (`PORT`, default 5000),
dual-stack:

- `GET /length/{N}` — response body of exactly `N` whitespace-free bytes.
- `POST /post` — returns the number of bytes received (GET returns help text).
- `GET /` — static sanity string.
- UDP — echoes each datagram back verbatim.

```bash
docker run --rm -e MODE=server -p 5000:5000 quay.io/tigeradev/rapidclient
```

## `client` mode

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

## How the e2e tests get this image

The tests reference the image via `images.RapidClientImage()`
(`e2e/pkg/utils/images/images.go`), which is env-driven:

- **PR CI on gcp-kubeadm:** PR builds have no registry push credential, so
  `.semaphore/end-to-end/scripts/phases/load_images.sh` builds this image from the
  PR source and imports it straight into each node's containerd (and the external
  node's docker), then exports `RAPIDCLIENT_TAG` (e.g. `pr-13105`). The tests pin
  that tag with `ImagePullPolicy: Never`.
- **Everything else** (other providers, scheduled runs, local dev): `RAPIDCLIENT_TAG`
  is unset and the tests use the published `quay.io/tigeradev/rapidclient:latest`.
  If you change this image and want a non-gcp-kubeadm run to use your build, publish
  it (post-merge `push-images/e2e-test.yml` promotion) or set `RAPIDCLIENT_TAG`
  yourself to a tag the cluster can pull.

## Integration with Tests

This tool can replace curl commands in tests for better reliability:

```bash
# Instead of:
curl --local-port 12345 -s http://service:8080/shell?cmd=hostname

# Use:
./rapidclient -url "http://service:8080/shell?cmd=hostname" -port 12345
```
