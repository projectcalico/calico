## Goldmane

Goldmane is a flow aggregation service. It provides a central, aggregated view of network flows in a Kubernetes cluster.

Some key packages:

- **proto/** defines the Flow structure and gRPC services provided by Goldmane.
- **pkg/aggregator/** collects flow information from across the cluster and aggregates those flows across all nodes, building a cluster-wide view of network activity.
- **pkg/collector/** provides a gRPC API that allows each Calico node instance to stream network flow information to a central location for aggregation and consumption.
- **pkg/emitter/** periodically emits time-aggregated flow information to a configured endpoint.
- **pkg/server/** allows for filtered querying of aggregated flow information.

### Connecting to Goldmane

The following provides an example of how to interact with Goldmane APIs on a Calico cluster from your local machine.

To connect to the Goldmane gRPC API in a production Calico cluster, you will need a few things:

- **Client certificate and key** - Goldmane mandates mTLS with clients.
- **CA certificate** to verify server TLS.

You can fetch these from a typical Calico cluster, for example the following commands collect calico/node client credentials for use:

```
kubectl get secret -n calico-system node-certs --template='{{index .data "tls.key"}}' | base64 -d > tls.key
kubectl get secret -n calico-system node-certs --template='{{index .data "tls.crt"}}' | base64 -d > tls.crt
kubectl get secret -n calico-system goldmane-key-pair --template='{{index .data "tls.crt"}}' | base64 -d > ca.crt
```

Goldmane itself is accessible via port-forwarding:

```
kubectl port-forward -n calico-system svc/goldmane 7443:7443
```

You can now write code using the API defined in [proto/api.proto](proto/api.proto), and access Goldmane APIs directly at `localhost:7443`. It may be useful to use the existing client code at [pkg/client/flowservice.go](pkg/client/flowservice.go) as a starting point.
