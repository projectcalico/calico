---
title: User console
description: A web-based user interface designed for multiple user skill sets and disciplines. 
calico_enterprise: true
---

With Calico Enterprise you get a web-based user interface that is intuitive and easy to use for multiple users across various skill sets and disciplines. The interface is designed for DevOps Engineers, Platform Engineers, Network Engineers, Security Engineers, and Compliance Managers. 

Most day-to-day operations for platform and DevOps teams use the Calico Enterprise APIs to execute automated CI/CD processes using policy-as-code (GitOps pushing config files). Those processes eliminate development and deployment bottlenecks, however, other teams are often less focused on automation and need a GUI and visual representation of the security posture.

Calico Enterprise exposes a web-based interface for all capabilities that provides security and networking teams with visibility into how your cluster is segmented and secured. The GUI spans all capabilities of Calico Enterprise, some highlights include:

- Policy dashboard
- Policy builder
- Flow visualizer
- Operations dashboard
- Compliance reports

### Policy dashboard

The policy dashboard is a visual representation of your policies and policy tiers that represents the current state of your security controls. The dashboard also enables a simpler understanding of how policies are implemented without diving into configuration files. You can drag and drop policies and tiers without having to manually write configuration files. The interface and APIs are also fully RBAC controlled.

![tiered-policy-board]({{site.baseurl}}/images/tiered-policy-board.png)

### Flow visualizer

Calico Enterprise monitors and logs all connectivity within your cluster into flow logs. Flow logs are required for security and compliance purposes, but are often used for basic debugging of connectivity issues and outages.

The Calico Enterprise Flow Visualizer helps you identify the source of issues interactively without having to review log files.

![flow-viz]({{site.baseurl}}/images/flow-viz.png)

### Operations dashboard

Calico Enterprise gives you a dashboard of connectivity and security within your Kubernetes cluster. When you log in, you can immediately see any denied traffic as well as traffic volumes that can help you forecast capacity requirements. The dashboard widgets all enable drill-down reports that provide you the details about network traffic and policies interacting with that traffic.

![operations-dashboard]({{site.baseurl}}/images/operations-dashboard.png)