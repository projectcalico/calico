# Windows Connectivity Tests

This directory contains test resources and scripts for validating network connectivity between Linux and Windows nodes in a Kubernetes cluster with Calico CNI.

## Prerequisites

- A Kubernetes cluster with both Linux and Windows nodes
- Calico CNI installed and configured for Windows (see `../aso/` for setup)
- `kubeconfig` file available at `../aso/kubeconfig`

## Test Components

| Component | Platform | Description |
|-----------|----------|-------------|
| `nginx` | Linux | Nginx web server pod and service |
| `porter` | Windows | Porter web server pod and service |
| `client` | Linux | Busybox pod for testing connectivity |

## Usage

```bash
./run-tests.sh
```

The script will:
1. Create the `demo` namespace
2. Deploy nginx, porter, and client pods
3. Wait for all pods to be ready (Windows pods may take up to 10 minutes)
4. Run connectivity tests:
   - **Test 1**: Linux client pod → Windows porter service (via DNS)
   - **Test 2**: Windows porter pod → Linux nginx service (via DNS)

## Test Topology

```
┌─────────────────┐         ┌─────────────────┐
│   Linux Node    │         │  Windows Node   │
│                 │         │                 │
│  ┌───────────┐  │         │  ┌───────────┐  │
│  │  client   │──┼────────►│  │  porter   │  │
│  └───────────┘  │  Test 1 │  └───────────┘  │
│                 │         │        │        │
│  ┌───────────┐  │         │        │        │
│  │   nginx   │◄─┼─────────┼────────┘        │
│  └───────────┘  │  Test 2 │                 │
└─────────────────┘         └─────────────────┘
```

## Expected Output

On success:
```
All connectivity tests passed!
```

On failure, the script will output which test failed and exit with code 1.

