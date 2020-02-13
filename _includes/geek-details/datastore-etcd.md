Calico stores the operational and configuration state of your cluster in a central datastore. If the datastore is unavailable, your Calico network continues operating, but cannot be updated (no new pods can be networked, no policy changes can be applied, etc.).

Calico has two datastore drivers you can choose from
- etcd - for direct connection to an etcd cluster
- Kubernetes - for connection to a Kubernetes API server

The advantages of using etcd as the datastore are:
- Allows you to run Calico on non-Kubernetes platforms (e.g. OpenStack)
- Allows separation of concerns between Kubernetes and Calico resources, for example allowing you to scale the datastores independently
- Allows you to run a Calico cluster that contains more than just a single Kubernetes cluster, for example, bare metal servers with Calico host protection interworking with a Kubernetes cluster or multiple Kubernetes clusters.

For completeness, the advantages of using Kubernetes as the datastore are:
- It doesn't require an extra datastore, so is simpler to install and manage
- You can use Kubernetes RBAC to control access to Calico resources
- You can use Kubernetes audit logging to generate audit logs of changes to Calico resources.
