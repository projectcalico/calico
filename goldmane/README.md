## Goldmane

Goldmane is a flow aggregation service. It provides a central, aggregated view of network flows in a Kubernetes cluster.

Some key packages:

- **proto/** defines the Flow structure and gRPC services provided by Goldmane.
- **pkg/aggregator/** collects flow information from across the cluster and aggregates those flows across all nodes, building a cluster-wide view of network activity.
- **pkg/collector/** provides a gRPC API that allows each Calico node instance to stream network flow information to a central location for aggregation and consumption.
- **pkg/emitter/** periodically emits time-aggregated flow information to a configured endpoint.
- **pkg/server/** allows for filtered querying of aggregated flow information.
