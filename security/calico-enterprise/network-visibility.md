---
title: Network visibility
description: Calico Enterprise provides deep network visibility into all ingress, egress, and pod-to-pod network traffic.
calico_enterprise: true
---

Calico Enterprise provides visibility into all ingress, egress, and pod-to-pod network traffic so you can easily:

- Meet internal and regulatory compliance requirements
- Identify and alert on unexpected behavior
- See exactly which network policies are allowing or deny a particular flow

### Flow logs 

Flow logs are a common requirement for any compliance framework. An auditor will generally need proof that your security controls are being enforced, and Calico Enterprise’s rich flow logs provide the evidence needed.

Flow logs also simplify debugging network policies and connectivity issues.

Each flow log entry includes Kubernetes metadata about the source and destination of each network connection, including:

- Source and destination pod name
- Source and destination namespace
- Source and destination pod labels
- Whether the connection was allowed or denied
- Each policy that applied to the connection and whether it accepted or denied the connection

Calico Enterprise is sensitive to storage requirements for flow logs.  Advanced aggregation techniques are used to provide accurate flow log records without the need for sampling that can lead to missing important flow events.

### Visualization 

Calico Enterprise provides a visual abstraction of flow logs with an interactive Network Flow Visualizer that enables you to explore accepted and denied flows within your cluster, understand traffic volumes, and dynamically zoom in or filter flows down to the namespaces and pods you are most interested in.

![visualizer]({{site.baseurl}}/images/visualizer.png)

### Identify anomalies

If you had an infected workload, would you know or be able to pinpoint which one?

Calico Enterprise detects and alerts on unexpected network behavior that can indicate a security breach. Alerts are generated for:

- Known attacks and exploits (e.g. exploits found at Shopify, Tesla, Atlassian)
- DOS attempts
- Attempted connections to botnets and command & control servers
- Abnormal flow volumes or flow patterns using machine learning

The Tigera threat research team keeps Calico Enterprise’s threat detection capabilities up to date, searching for new and known vulnerabilities.