---
title: Policy workflow
description: Implement a workflow process for creating and enforcing network policies to reduce connectivity issues.
calico_enterprise: true
---

Implementing a process around creating and enforcing policies will reduce unexpected connectivity issues. Calico Enterprise helps you do this.

![policy-workflow]({{site.baseurl}}/images/policy-workflow.png)

### Policy recommendation

Calico Enterprise can auto-generate a policy based on ingress and egress traffic between existing services. This can help you implement policy when you are not certain all of the interdependent connections between services.

Policies are called ‘Recommended’ because they are based on existing traffic flows that are observable, and you can also modify the policy if there are other connections you anticipate that are not occurring during the observation period.

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
