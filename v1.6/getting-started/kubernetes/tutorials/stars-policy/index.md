---
title: Stars Policy Demo
canonical_url: 'https://docs.projectcalico.org/v3.6/getting-started/kubernetes/tutorials/stars-policy/'
---
The included demo sets up a frontend and backend service, as well as a client service, all
running on Kubernetes.  It then configures network policy on each service.

## Pre-requisites

To create a Kubernetes cluster which supports the Kubernetes network policy API, follow
one of our [getting started guides]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes).  

Before following this guide, you will need to download the required manifests.

    git clone https://github.com/projectcalico/calico.git

Then, change into the directory for this guide:

    cd calico/{{page.version}}/getting-started/kubernetes/tutorials/stars-policy

## Running the stars example

### 1) Create the frontend, backend, client, and management-ui apps.

```shell
kubectl create -f manifests/
```

Wait for all the pods to enter `Running` state.

```shell
watch kubectl get pods --all-namespaces
```
> Note that it may take several minutes to download the necessary Docker images for this demo.

The management UI runs as a `NodePort` Service on Kubernetes, and shows the connectivity
of the Services in this example.

If you're running the vagrant cluster, you can view the UI by visiting `http://172.18.18.102:30002` in a browser.  For other clusters, accessing
the web UI may vary.

Once all the pods are started, they should have full connectivity. You can see this by visiting the UI.  Each service is
represented by a single node in the graph.

- `backend` -> Node "B"
- `frontend` -> Node "F"
- `client` -> Node "C"

### 2) Enable isolation

```shell
kubectl annotate ns stars "net.beta.kubernetes.io/network-policy={\"ingress\":{\"isolation\":\"DefaultDeny\"}}"
kubectl annotate ns client "net.beta.kubernetes.io/network-policy={\"ingress\":{\"isolation\":\"DefaultDeny\"}}"
```

This will prevent all access to the frontend, backend, and client Services.

Refresh the management UI (it may take up to 10 seconds for changes to be reflected in the UI).
Now that we've enabled isolation, the UI can no longer access the pods, and so they will no longer show up in the UI.

### 3) Allow the UI to access the Services using NetworkPolicy objects

```shell
# Allow access from the management UI.
kubectl create -f policies/allow-ui.yaml
kubectl create -f policies/allow-ui-client.yaml
```

After a few seconds, refresh the UI - it should now show the Services, but they should not be able to access each other any more.

### 4) Create the "backend-policy.yaml" file to allow traffic from the frontend to the backend.

```shell
kubectl create -f policies/backend-policy.yaml
```

Refresh the UI.  You should see the following:

- The frontend can now access the backend (on TCP port 6379 only).
- The backend cannot access the frontend at all.
- The client cannot access the frontend, nor can it access the backend.

### 5) Expose the frontend service to the `client` namespace.

```shell
kubectl create -f policies/frontend-policy.yaml
```

The client can now access the frontend, but not the backend.  Neither the frontend nor the backend
can initiate connections to the client.  The frontend can still access the backend.
