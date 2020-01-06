---
title: Monitor Calico component metrics
---

### Big picture

Use Prometheus configured for {{site.prodname}} components to get valuable metrics about the health of your network.

### Value

Using the open-source Prometheus monitoring and alerting toolkit, you can view time-series metrics from {{site.prodname}} components in the Prometheus or Grafana interfaces.  

### Features

This how-to guide uses the following {{site.prodname}} features:

**Felix** and **Typha** components configured with Prometheus configuration parameters (for consumption by Prometheus).

### Concepts

#### About Prometheus

The Prometheus monitoring tool scrapes metrics from instrumented jobs and displays time series data in a visualizer (such as Grafana). For {{site.prodname}}, the “jobs” that Prometheus can harvest metrics from are the Felix and Typha components. 

#### About {{site.prodname}} Felix and Typha components

**Felix** is a daemon that runs on every machine that provides endpoints ({{site.prodname}} nodes). Felix is the brains of {{site.prodname}}. Typha is an optional daemon that extends Felix to scale traffic between {{site.prodname}} nodes and the datastore. **Typha** is used to avoid bottlenecks and performance issues in the datastore when you have over 50 {{site.prodname}} nodes. 

You can configure Felix and/or Typha to provide metrics to Prometheus.


### How to

#### Enable Prometheus metrics for and Felix and Typha

1. Using the Prometheus documentation, configure one or more [Prometheus servers](https://prometheus.io/docs/introduction/overview/).  
1. To enable [Felix]({{ site.baseurl }}/reference/felix/configuration) for metrics, set **PrometheusMetricsEnabled = true**.
1. To enable [Typha]({{ site.baseurl }}/reference/typha/configuration) for metrics, set **PrometheusMetricsEnabled = true**.
1. If required for Felix and/or Typha, change the default TCP port (9091) for your Prometheus metrics server using the parameter, **PrometheusMetricsPort**.

#### Best practices

If you enable {{site.prodname}} metrics to Prometheus, a best practice is to use network policy to limit access to the {{site.prodname}} metrics endpoints. For details, see [Secure {{site.prodname}} Prometheus endpoints]({{ site.baseurl }}/security/comms/secure-metrics).  

If you are not using Prometheus metrics, we recommend disabling the Prometheus ports entirely for more security. 
