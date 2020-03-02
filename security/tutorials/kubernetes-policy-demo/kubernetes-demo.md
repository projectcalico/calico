---
title: Kubernetes policy, demo
description: An interactive demo that visually shows how applying Kubernetes policy allows and denies connections. 
canonical_url: '/security/tutorials/kubernetes-policy-demo/kubernetes-demo'
---
The included demo sets up a frontend and backend service, as well as a client service, all
running on Kubernetes.  It then configures network policy on each service.

## Prerequisites

To create a Kubernetes cluster which supports the Kubernetes network policy API, follow
one of our [getting started guides]({{ site.baseurl }}/getting-started/).

## Running the stars example

### 1) Create the frontend, backend, client, and management-ui apps.

```shell
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/manifests/00-namespace.yaml" | absolute_url }}
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/manifests/01-management-ui.yaml" | absolute_url }}
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/manifests/02-backend.yaml" | absolute_url }}
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/manifests/03-frontend.yaml" | absolute_url }}
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/manifests/04-client.yaml" | absolute_url }}
```

Wait for all the pods to enter `Running` state.

```bash
kubectl get pods --all-namespaces --watch
```
> Note that it may take several minutes to download the necessary Docker images for this demo.

The management UI runs as a `NodePort` Service on Kubernetes, and shows the connectivity
of the Services in this example.

You can view the UI by visiting `http://<k8s-node-ip>:30002` in a browser.

Once all the pods are started, they should have full connectivity. You can see this by visiting the UI.  Each service is
represented by a single node in the graph.

- `backend` -> Node "B"
- `frontend` -> Node "F"
- `client` -> Node "C"

### 2) Enable isolation

Running following commands will prevent all access to the frontend, backend, and client Services.

```shell
kubectl create -n stars -f {{ "/security/tutorials/kubernetes-policy-demo/policies/default-deny.yaml" | absolute_url }}
kubectl create -n client -f {{ "/security/tutorials/kubernetes-policy-demo/policies/default-deny.yaml" | absolute_url }}
```

#### Confirm isolation

Refresh the management UI (it may take up to 10 seconds for changes to be reflected in the UI).
Now that we've enabled isolation, the UI can no longer access the pods, and so they will no longer show up in the UI.

### 3) Allow the UI to access the services using network policy objects

Apply the following YAMLs to allow access from the management UI.

```shell
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/policies/allow-ui.yaml" | absolute_url }}
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/policies/allow-ui-client.yaml" | absolute_url }}
```

After a few seconds, refresh the UI - it should now show the Services, but they should not be able to access each other any more.

### 4) Create the backend-policy.yaml file to allow traffic from the frontend to the backend

```shell
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/policies/backend-policy.yaml" | absolute_url }}
```

Refresh the UI.  You should see the following:

- The frontend can now access the backend (on TCP port 6379 only).
- The backend cannot access the frontend at all.
- The client cannot access the frontend, nor can it access the backend.

### 5) Expose the frontend service to the client namespace

```shell
kubectl create -f {{ "/security/tutorials/kubernetes-policy-demo/policies/frontend-policy.yaml" | absolute_url }}
```

The client can now access the frontend, but not the backend.  Neither the frontend nor the backend
can initiate connections to the client.  The frontend can still access the backend.

To use {{site.prodname}} to enforce egress policy on Kubernetes pods, see [the advanced policy demo]({{ site.baseurl }}/security/tutorials/kubernetes-policy-advanced).

### 6) (Optional) Clean up the demo environment

You can clean up the demo by deleting the demo Namespaces:

```bash
kubectl delete ns client stars management-ui
```
