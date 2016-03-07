# A tool for managing NetworkPolicy objects
```
wget https://github.com/projectcalico/k8s-policy/releases/download/v0.1.0/policy
```

It is configurable via environment variables. 
```
export KUBE_API_ROOT=http://localhost:8080
export KUBE_AUTH_TOKEN="<auth_token>"
```
> You can find your auth token using `kubectl describe secret`

To create a new network policy from a file:
```
cat policy.yaml | policy create
```

To delete a network policy:
```
policy delete <namespace> <policy-name>
```

To list all `NetworkPolicy` objects:
```
policy list
```

To get details about a specific `NetworkPolicy`:
```
policy get <namespace> <policy-name>
```
