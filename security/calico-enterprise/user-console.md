---
title: Calico Enterprise user console
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

### Policy workflow

Implementing a process around creating and enforcing policies will reduce unexpected connectivity issues. Calico Enterprise helps you do this.

![policy-workflow]({{site.baseurl}}/images/policy-workflow.png)

### Policy recommendation

Calico Enterprise can auto-generate a policy based on ingress and egress traffic between existing services. This can help you implement policy when you are not certain all of the interdependent connections between services.

Policies are called ‘Recommended’ because they are based on existing traffic flows that are observable, and you can also modify the policy if there are other connections you anticipate that are not occuring during the observation period.

Policy recommendation is the fastest way to implement Network Policies in an existing cluster if you are unsure what policy is needed.

![policy-recommendation]({{site.baseurl}}/images/policy-recommendation.png)

### Policy builder

You can use the Policy Builder to construct or modify Kubernetes and Calico network policies without the need for editing YAML or JSON policy files. The interface understands current labels and abstracts the structure of configuration files to enable you, as well as other Kubernetes users, a fast and easy way to implement accurate, comprehensive, and bug-free policies.

![policy-builder]({{site.baseurl}}/images/policy-builder.png)

### Policy preview

You can preview the effects of any policy change using Calico Enterprise. The proposed policy change is simulated against historical network flow data to produce a graphic representation of all changed flows. Policy preview makes it easy to catch mistakes in policy at the time you are authoring the policy, increasing efficiency and confidence in your policy workflow.

### Policy stages

Calico Enterprise policies can be run in either a “committed” or “staged” mode. Policies running in a staged mode will report on traffic that would have been allowed or denied by the policy, but will not enforce its rule. This enables policy changes to be safely rolled out to your cluster and observed until you feel comfortable committing and enforcing the change.

![policy-options]({{site.baseurl}}/images/policy-options.png)
