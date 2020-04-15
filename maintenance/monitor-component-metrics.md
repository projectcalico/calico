---
title: Monitor Calico component metrics
description: Use open source Prometheus for monitoring and alerting on Calico components.
---

* TOC
{:toc}

# Introduction

Use Prometheus configured for {{site.prodname}} components to get valuable metrics about the health of your network. 
Using the open-source Prometheus monitoring and alerting toolkit, you can view time-series metrics from {{site.prodname}} components in the Prometheus or Grafana interfaces. The Prometheus monitoring tool scrapes metrics from instrumented jobs and displays time series data in a visualizer (such as Grafana). For {{site.prodname}}, the “jobs” that Prometheus can harvest metrics from are the Felix and Typha components. Felix is a daemon that runs on every machine that provides endpoints ({{site.prodname}} nodes. Felix is the brains of {{site.prodname}}. Typha is an optional daemon that extends Felix to scale traffic between {{site.prodname}} nodes and the datastore. Typha is used to avoid bottlenecks and performance issues in the datastore when you have over 50 {{site.prodname}} nodes.

## Requirements

In this tutorial we assume that you have completed all other introductory sections and possess a running Kubernetes cluster with {{site.prodname}} and calicoctl installed.

> **Note** Typha implementation is optional, if you don't have Typha in your cluster you should skip step 4 and 7 of this tutorial.
   {: .alert .alert-warning}

# How to

In this section we will go through the necessary steps to implement basic monitoring with Prometheus. You will assign required permission to a service account, create a permanent configuration and store it via configmaps, create services to discover endpoints dynamically, create a Prometheus pod, change Felix configuration and create a basic graph using consumed Felix metrics.

## 1. Allowing user access to metrics

You need to give a user account required permissions to be able to collect information from the nodes.

> **Note**: A comprehensive guide to user roles and authentication can be [found at this link](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
   {: .alert .alert-info}

```bash
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: prometheus-rbac
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF
```
## 2. Creating permanent config file

Since containers are ephemeral, it is best to store configuration file to a permanent storage solution and link it to your pod. 

> **Note**: A comprehensive guide about configuration file can be [found at this link](https://prometheus.io/docs/prometheus/latest/configuration/configuration/).
   {: .alert .alert-info}

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
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
        regex: felix-demo-svc
        replacement: $1
        action: keep
    - job_name: 'typha_metrics'
      scrape_interval: 5s
      scheme: http
      kubernetes_sd_configs:
      - role: endpoints
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_name]
        regex: typha-demo-svc
        replacement: $1
        action: keep
EOF
```

## 3. Creating a service to expose Felix metrics

Your prometheus configuration is going to check services and catch endpoints related to felix-demo-svc service, you need to create a service with that name to expose Felix metrics. This will help in discovery of your services and **makes** it dynamic. 

> **Note**: Felix uses port 9091 TCP to publish its metrics.
   {: .alert .alert-info}

``` bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: felix-demo-svc
  namespace: kube-system
spec:
  selector:
    k8s-app: calico-node
  ports:
  - port: 9091
    targetPort: 9091
EOF
```

## 4. Creating a service to expose Typha metrics

You need to create a service that exposes your typha instance metrics to Prometheus.

> **Note**: Typha uses **port 9091** TCP to publish its metrics. However, in AWS Implementation of calico port is set to TCP Port 9093 via **TYPHA_PROMETHEUSMETRICSPORT** environment variable.
   {: .alert .alert-warning}

``` bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: typha-demo-svc
  namespace: kube-system
spec:
  selector:
    k8s-app: calico-typha
  ports:
  - port: 9093
    targetPort: 9093
EOF
```

## 5. Creating Prometheus pod

Now that you allowed the user to view the metrics and have a valid config file for your Prometheus, it's time to create the pod.

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: prometheus-pod
  labels:
    app: prometheus-pod
    role: monitoring
spec:
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

Check your cluster running pods to assure pod creation was successful.
    
    
```bash
kubectl get pods prometheus-pod
```
It should return something like the following.

```
NAME             READY   STATUS    RESTARTS   AGE
prometheus-pod   1/1     Running   0          16s
```

You can access prometheus dashboard by using port-forwarding feature.

```bash
kubectl port-forward pod/prometheus-pod 9090:9090
```

Browse to [http://localhost:9090](http://localhost:9090) you should be able to see prometheus dashboard.

## 6. Enabling Felix metrics

Prometheus metric microservice is set to **false** by default. You have to manually change your Felix configuration (**prometheusMetricsEnabled**) via calicoctl in order to use this feature.

> **Note**: A comprehensive list of configuration values can be [found at this link]({{ site.baseurl }}/reference/felix/configuration).
   {: .alert .alert-info}



```bash
calicoctl replace -f - <<EOF
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  creationTimestamp: null
  name: default
spec:
  bpfLogLevel: ""
  logSeverityScreen: Info
  prometheusMetricsEnabled: true
  reportingInterval: 0s
EOF
```

You are almost done. browse to Prometheus dashboard and type **felix_active_local_endpoints** in the Expression input textbox then hit the execute button. Console table should be populated with the node ips in your cluster.

> **Note**: A comprehensive list of metrics can be [found at this link]({{ site.baseurl }}/reference/felix/prometheus).
   {: .alert .alert-info}

Push the Add Graph button, You should be able to see the metric plotted on a Graph.

## 7. Explanation for Typha metrics

If you are using Typha you can enable metrics to be consumed by Prometheus as well. This section we assume that you have an AWS eks cluster setup and Typha enabled. {{site.prodname}} AWS implementation uses **TYPHA_PROMETHEUSGOMETRICSENABLED** environment variable by default.
If you are uncertain about typha in your cluster you can examine it by running the following code

```bash
kubectl get pods -A | grep typha
```

This should give you a result similar to following

> **Note** The name suffix of pods shown below was dynamically generated. Your typha instance might have a different suffix.
   {: .alert .alert-info}

```
kube-system     calico-typha-56fccfcdc4-z27xj                         1/1     Running   0          28h
kube-system     calico-typha-horizontal-autoscaler-74f77cd87c-6hx27   1/1     Running   0          28h
```



# Cleanup

By executing below commands, you will delete all the resources and services created by following this tutorial.

```bash
kubectl delete svc felix-demo-svc -n kube-system
kubectl delete svc typha-demo-svc -n kube-system
kubectl delete pod prometheus-pod
kubectl delete configmap prometheus-config
kubectl delete clusterrolebinding prometheus-rbac
```

# Best practices

If you enable {{site.prodname}} metrics to Prometheus, a best practice is to use network policy to limit access to the {{site.prodname}} metrics endpoints. For details, see [Secure {{site.prodname}} Prometheus endpoints]({{ site.baseurl }}/security/comms/secure-metrics).  

If you are not using Prometheus metrics, we recommend disabling the Prometheus ports entirely for more security. 
