You should configure a `node` resource for each
host running Felix.  In this case, the database is initialized after
creating the first `node` resource.  For a deployment that does not include
the {{site.prodname}}/BGP integration, the specification of a node resource just
requires the name of the node; for most deployments this will be the same as the
hostname.

```bash
calicoctl create -f - <<EOF
- apiVersion: projectcalico.org/v3
  kind: Node
  metadata:
    name: <node name or hostname>
EOF
```

The Felix logs should transition from periodic notifications
that Felix is in the state `wait-for-ready` to a stream of initialization
messages.
