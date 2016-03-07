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

```
$ policy help
Usage:
    policy create [--namespace=<namespace>] [-f <filename>]
    policy delete [--namespace=<namespace>] <policy>
    policy get [--namespace=<namespace>] <policy>
    policy list
    policy help

Description:
    Helper for creating, deleting, and listing Kubernetes
    NetworkPolicy objects.

Options:
    --namespace=<namespace>             Kubernetes namespace to use.
                                        [default: default]
    -f --file                           Create from the provided file.
```
