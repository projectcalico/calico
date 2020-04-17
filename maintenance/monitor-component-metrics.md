---
title: Monitor Calico component metrics
description: Use open source Prometheus for monitoring and alerting on Calico components.
---

## Big picture

Use Prometheus configured for {{site.prodname}} components to get valuable metrics about the health of {{site.prodname}}.

## Value

Using the open-source Prometheus monitoring and alerting toolkit, you can view time-series metrics from {{site.prodname}} components in the Prometheus or Grafana interfaces.  

## Features

This how-to guide uses the following {{site.prodname}} features:

**Felix** and **Typha** components configured with Prometheus configuration parameters (for consumption by Prometheus).

## Concepts

### About Prometheus

The Prometheus monitoring tool scrapes metrics from instrumented jobs and displays time series data in a visualizer (such as Grafana). For {{site.prodname}}, the “jobs” that Prometheus can harvest metrics from are the Felix and Typha components. 

### About {{site.prodname}} Felix and Typha components

**Felix** is a daemon that runs on every machine that provides endpoints ({{site.prodname}} nodes). Felix is the brains of {{site.prodname}}. Typha is an optional daemon that extends Felix to scale traffic between {{site.prodname}} nodes and the datastore. **Typha** is used to avoid bottlenecks and performance issues in the datastore when you have over 50 {{site.prodname}} nodes. 

You can configure Felix and/or Typha to provide metrics to Prometheus.

## Before you begin...

In this tutorial we assume that you have completed all other introductory tutorials and possess a running Kubernetes cluster with {{site.prodname}}, calicoctl and kubectl installed.

## How to

This tutorial will go through the necessary steps to implement basic monitoring of {{site.prodname}} with Prometheus.
1. This section will teach you how to configure {{site.prodname}} to export its own metrics.
2. In this section you will learn to isolate the resources and create necessary permissions for future steps.
3. In this section you will configure Prometheus and create its instance in the cluster.
4. You will be able to visit Prometheus dashboard and create a simple graph.


### 1. Configure Calico to enable metrics reporting
#### Felix configuration
Felix prometheus metrics are **disabled** by default. You have to manually change your Felix configuration (**prometheusMetricsEnabled**) via calicoctl in order to use this feature.

> **Note**: A comprehensive list of configuration values can be [found at this link]({{ site.baseurl }}/reference/felix/configuration).
   {: .alert .alert-info}

```bash
calicoctl patch felixConfiguration default  --patch '{"spec":{"prometheusMetricsEnabled": true}}'
```
You should see an output like below:
```
Successfully patched 1 'FelixConfiguration' resource
```

##### **Creating a service to expose Felix metrics**
By using services you will be able to dynamically discover endpoints. Here you will create a service named `felix-metrics-svc` which will receive requests from port 9091 and forward it to port 9090 of pods that are participating in `kube-system` namespace and share `k8s-app: calico-node` label.

> **Note**: Felix by default uses port 9091 TCP to publish its metrics.
   {: .alert .alert-info}

``` bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: felix-metrics-svc
  namespace: kube-system
spec:
  selector:
    k8s-app: calico-node
  ports:
  - port: 9091
    targetPort: 9091
EOF
```

#### Typha Configuration
> **Note** Typha implementation is optional, if you don't have Typha in your cluster you should skip [Typha configuration]({{ site.baseurl }}/maintenance/monitor-component-metrics#typha-configuration) section.
   {: .alert .alert-danger}

If you are uncertain about `Typha` in your cluster execute the following code:

```bash
kubectl get pods -A | grep typha
```
If your result is similar to what is shown below you are using Typha in your cluster.

> **Note** The name suffix of pods shown below was dynamically generated. Your typha instance might have a different suffix.
   {: .alert .alert-warning}

```
kube-system     calico-typha-56fccfcdc4-z27xj                         1/1     Running   0          28h
kube-system     calico-typha-horizontal-autoscaler-74f77cd87c-6hx27   1/1     Running   0          28h
```

You can enable Typha metrics to be consumed by Prometheus via [two ways](http://localhost:4000/reference/typha/configuration).
##### **Creating a service to expose Typha metrics**

By using services you will be able to dynamically discover endpoints. Here you will create a service named `typha-metrics-svc` which will receive requests from port 9091 and forward it to port 9090 of pods that are participating in `kube-system` namespace and share `k8s-app: calico-typha` label.

> **Note**: Typha uses **port 9091** TCP by default to publish its metrics. However, if {{site.prodname}} yaml is installed by using [Amazon yaml file](https://github.com/aws/amazon-vpc-cni-k8s/blob/b001dc6a8fff52926ed9a93ee6c4104f02d365ab/config/v1.5/calico.yaml#L535-L536) this port is set to 9093 via **TYPHA_PROMETHEUSMETRICSPORT** environment variable.
   {: .alert .alert-warning}

``` bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: typha-metrics-svc
  namespace: kube-system
spec:
  selector:
    k8s-app: calico-typha
  ports:
  - port: 9093
    targetPort: 9093
EOF
```

### 2. Cluster preparation

#### Namespace creation

`Namespace` isolates resources in your cluster. Here you will create a Namespace called `calico-monitoring` to hold your monitoring resources.
> **Note**: Kubernetes namespaces guide can be [found at this link](https://kubernetes.io/docs/tasks/administer-cluster/namespaces/).
   {: .alert .alert-info}

```bash
kubectl apply -f -<<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: calico-monitoring
  labels:
    app:  ns-calico-monitoring
    role: monitoring
EOF
```

####  Service account creation

You need to give Prometheus a serviceAccount with required permissions to collect information from {{site.prodname}}.

> **Note**: A comprehensive guide to user roles and authentication can be [found at this link](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
   {: .alert .alert-info}

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: calico-prometheus-user
rules:
- apiGroups: [""]
  resources:
  - endpoints
  - services
  - pods
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["/metrics"]
  verbs: ["get"]
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-prometheus-user
  namespace: calico-monitoring
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: calico-prometheus-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-prometheus-user
subjects:
- kind: ServiceAccount
  name: calico-prometheus-user
  namespace: calico-monitoring
EOF
```
### 3. Install prometheus
#### Creating prometheus config file

Since containers are ephemeral, it is best to store configuration file to a permanent storage solution and link it to your pod. 

> **Note**: A comprehensive guide about configuration file can be [found at this link](https://prometheus.io/docs/prometheus/latest/configuration/configuration/).
   {: .alert .alert-info}

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: calico-monitoring
data:
  prometheus.yml: |-
    global:
      scrape_interval:   15s
      external_labels:
        monitor: 'tutorial-monitor'
    scrape_configs:
    - job_name: 'prometheus'
      scrape_interval: 5s
      static_configs:
      - targets: ['localhost:9090']
    - job_name: 'felix_metrics'
      scrape_interval: 5s
      scheme: http
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        regex: felix-metrics-svc
        replacement: $1
        action: keep
    - job_name: 'typha_metrics'
      scrape_interval: 5s
      scheme: http
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        regex: typha-metrics-svc
        replacement: $1
        action: keep
EOF
```
#### Creating Prometheus pod

Now that you have a `serviceaccount` with permissions to gather metrics and have a valid config file for your Prometheus, it's time to create the pod.

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: prometheus-pod
  namespace: calico-monitoring
  labels:
    app: prometheus-pod
    role: monitoring
spec:
  serviceAccountName: calico-prometheus-user
  containers:
  - name: prometheus-pod
    image: prom/prometheus
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
    volumeMounts:
    - name: config-volume
      mountPath: /etc/prometheus/prometheus.yml
      subPath: prometheus.yml
    ports:
    - containerPort: 9090
  volumes:
  - name: config-volume
    configMap:
      name: prometheus-config
EOF
```

Check your cluster pods to assure pod creation was successful and prometheus pod is `Running`.
    
    
```bash
kubectl get pods prometheus-pod -n calico-monitoring
```
It should return something like the following.

```
NAME             READY   STATUS    RESTARTS   AGE
prometheus-pod   1/1     Running   0          16s
```
### 4. View metrics
You can access prometheus dashboard by using port-forwarding feature.

```bash
kubectl port-forward pod/prometheus-pod 9090:9090 -n calico-monitoring
```

Browse to [http://localhost:9090](http://localhost:9090) you should be able to see prometheus dashboard. Type **felix_active_local_endpoints** in the Expression input textbox then hit the execute button. Console table should be populated with all your nodes and quantity of endpoints in each of them.

> **Note**: A comprehensive list of metrics can be [found at this link]({{ site.baseurl }}/reference/felix/prometheus).
   {: .alert .alert-info}

Push the `Add Graph` button, You should be able to see the metric plotted on a Graph.

## Cleanup

By executing below commands, you will delete all the resources and services created by following this tutorial.

```bash
kubectl delete service felix-metrics-svc -n kube-system
kubectl delete service typha-metrics-svc -n kube-system
kubectl delete namespace calico-monitoring
kubectl delete ClusterRole calico-prometheus-user
kubectl delete ServiceAccount calico-prometheus-user
kubectl delete clusterrolebinding calico-prometheus-user
```

## Best practices

If you enable {{site.prodname}} metrics to Prometheus, a best practice is to use network policy to limit access to the {{site.prodname}} metrics endpoints. For details, see [Secure {{site.prodname}} Prometheus endpoints]({{ site.baseurl }}/security/comms/secure-metrics).  

If you are not using Prometheus metrics, we recommend disabling the Prometheus ports entirely for more security. 
