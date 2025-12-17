# Gateway API Conformance Tests

This directory contains Gateway API conformance tests for Calico.

## Overview

These tests verify that Calico's Gateway API implementation (using Envoy Gateway) conforms to the official Kubernetes Gateway API specification.

## Test Structure

- `manifests/` - Gateway API resource definitions (GatewayClass, Gateway)
- Test binary: `e2e/bin/gateway/e2e.test`

## Running Tests

### Prerequisites

- Docker (for kind)
- Go 1.21+
- Make
- kubectl (auto-downloaded to `hack/test/kind/kubectl`)

### Complete Local Workflow

```bash
# 1. Build test binaries (including Gateway API tests)
make -C e2e build

# 2. Create kind cluster and deploy Calico (~5-10 minutes)
make -C node kind-k8st-setup

# 3. Deploy Envoy Gateway
export KUBECONFIG=hack/test/kind/kind-kubeconfig.yaml
kubectl apply -f https://github.com/envoyproxy/gateway/releases/download/v1.5.6/install.yaml
kubectl wait --timeout=5m -n envoy-gateway-system deployment/envoy-gateway --for=condition=Available

# 4. Create test infrastructure namespace
kubectl create namespace gateway-conformance-infra

# 5. Apply Gateway API resources
kubectl apply -f gateway/test/conformance/manifests/

# 6. Wait for Gateway to be ready
kubectl wait --timeout=5m -n gateway-conformance-infra gateway/gateway-conformance-default --for=condition=Programmed

# 7. Run Gateway API conformance tests
make e2e-run-gateway-test

# 8. Clean up when done
make -C node kind-k8st-cleanup
```

### Quick Run (if cluster already exists)

```bash
# Just run the tests against existing cluster
export KUBECONFIG=hack/test/kind/kind-kubeconfig.yaml
make e2e-run-gateway-test
```

### Running Specific Tests

```bash
# Run with verbose output
KUBECONFIG=hack/test/kind/kind-kubeconfig.yaml \
  ./e2e/bin/gateway/e2e.test \
  -gateway-class=calico-gateway \
  -supported-features=Gateway,HTTPRoute \
  -test.v

# Run with debug output
KUBECONFIG=hack/test/kind/kind-kubeconfig.yaml \
  ./e2e/bin/gateway/e2e.test \
  -gateway-class=calico-gateway \
  -supported-features=Gateway,HTTPRoute \
  -show-debug=true
```

## Conformance Profiles

Currently tested profiles:
- **Gateway** - Core Gateway resource functionality
- **HTTPRoute** - HTTP routing features

Future profiles to consider:
- **TLSRoute** - TLS routing
- **ReferenceGrant** - Cross-namespace references
- **Mesh** - Service mesh features

## Configuration

Tests can be configured via command-line flags:

### Available Flags

- `-gateway-class` - GatewayClass name (default: `gateway-conformance`)
- `-supported-features` - Comma-separated list of supported features
- `-exempt-features` - Comma-separated list of features to skip
- `-cleanup-base-resources` - Cleanup resources after tests (default: `true`)
- `-show-debug` - Enable debug output (default: `false`)
- `-enable-all-supported-features` - Enable all supported features (default: `false`)

### Example Configurations

**Test only Gateway features:**
```bash
./e2e/bin/gateway/e2e.test -gateway-class=calico-gateway -supported-features=Gateway
```

**Test with different GatewayClass:**
```bash
./e2e/bin/gateway/e2e.test -gateway-class=my-gateway -supported-features=Gateway,HTTPRoute
```

**Skip cleanup for debugging:**
```bash
./e2e/bin/gateway/e2e.test -gateway-class=calico-gateway -cleanup-base-resources=false
```

## Test Reports

Conformance test reports are generated in the `report/` directory:

- `report/junit.xml` - JUnit test results (for CI integration)
- Test output in console

### Viewing Reports Locally

```bash
# View test summary
cat report/junit.xml

# View detailed logs
kubectl logs -n gateway-conformance-infra <pod-name>
```

## CI Integration

Tests run automatically in SemaphoreCI when changes are detected in:
- `gateway/` directory
- `e2e/cmd/gateway/` directory
- `third_party/envoy-gateway/` directory

CI job configuration: `.semaphore/semaphore.yml.d/blocks/20-gateway-conformance.yml`

### CI Artifacts

Reports are automatically uploaded to SemaphoreCI artifacts:
- JUnit XML reports
- Test logs
- Conformance reports

Artifacts are available for 2 weeks after job completion.

## Troubleshooting

### Gateway not becoming ready

```bash
# Check Gateway status
kubectl get gateway -n gateway-conformance-infra gateway-conformance-default -o yaml

# Check Envoy Gateway logs
kubectl logs -n envoy-gateway-system -l control-plane=envoy-gateway

# Check GatewayClass status
kubectl get gatewayclass calico-gateway -o yaml
```

### Tests failing

```bash
# View detailed test output
./e2e/bin/gateway/e2e.test -show-debug=true -test.v

# Check for resource conflicts
kubectl get all -n gateway-conformance-infra

# Review Gateway API CRDs
kubectl get crd | grep gateway.networking.k8s.io
```

### Cleanup issues

```bash
# Manual cleanup of Gateway resources
kubectl delete namespace gateway-conformance-infra
kubectl delete gatewayclass calico-gateway

# Clean up Envoy Gateway
kubectl delete namespace envoy-gateway-system

# Restart kind cluster if needed
make -C node kind-k8st-cleanup
make -C node kind-k8st-setup
```

## Development

### Rebuilding Tests After Code Changes

```bash
# Rebuild just the Gateway API test binary
cd e2e
go test ./cmd/gateway -c -o bin/gateway/e2e.test

# Or rebuild all e2e tests
make build
```

### Fast Iteration

```bash
# Make code changes...

# Rebuild test binary (fast)
cd e2e && go test ./cmd/gateway -c -o bin/gateway/e2e.test

# Re-run tests (cluster already exists)
KUBECONFIG=../hack/test/kind/kind-kubeconfig.yaml ./bin/gateway/e2e.test \
  -gateway-class=calico-gateway \
  -supported-features=Gateway,HTTPRoute
```

## Resources

- Gateway API Specification: https://gateway-api.sigs.k8s.io/
- Gateway API Conformance: https://gateway-api.sigs.k8s.io/concepts/conformance/
- Envoy Gateway Documentation: https://gateway.envoyproxy.io/
- Calico Documentation: https://docs.tigera.io/calico/latest/

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Calico and Gateway API documentation
3. Open an issue in the Calico repository
4. Check SemaphoreCI logs for CI-specific issues
