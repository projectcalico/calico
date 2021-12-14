---
title: Advanced compliance controls
description: Learn about Calico Enterprise features that help security teams provide evidence and proof of compliance. 
calico_enterprise: true
---

Your security team may ask you to implement certain security controls. A simple example is environment isolation (dev versus prod); more complex examples include HIPAA or PCI-DSS controls.

For most security teams, setting up and enforcing Calico policy is not sufficient to meet their needs.
Security teams need additional controls to ensure their policies have precedence and are evaluated first before other policies. They need to see proof that the controls are in place, being enforced, and working as expected (logs, evidence reports, version history).

Calico Enterprise adds several features that satisfy the security team’s requirements including:

- Policy tiers
- Flow logs
- Audit logs
- Configuration auditing
- Compliance reports

### Policy tiers

Policy tiers are ordered collections of Calico policies. Policy tiers enable privileged users to define security policies that take precedence over other user’s policies. A couple of common use cases include:

- A security team needs to define policies that must be evaluated before any other policies - e.g. ensuring dev cannot connect to communicate with prod
- The Kubernetes platform owner may define rules that limit which Kubernetes APIs or other management interfaces pods can connect to

![tiered-policy-board]({{site.baseurl}}/images/tiered-policy-board.png)

All Calico Enterprise resources support Kubernetes RBAC permissions, including tiers, and policies within tiers. This enables delegation of trust across teams (e.g. ensuring that the security tier can only be changed by the security team, and that dev team policies are always lower precedence than security team policies).

### Flow logs

To generate proof for your security team that your policies are being enforced and behaving as intended, Calico Enterprise generates and stores flow logs that can be queried to provide reports to your security team and auditors. Accurate flow log data is a common requirement for many compliance frameworks. 

Calico Enterprise flow logs contain important Kubernetes metadata including (but not limited to):

- Source and destination namespaces
- Source and destination pods
- Labels for source and destination pods
- Originating IP address for ingress connections
- Which policies evaluated the connection and whether the policy allowed or denied the connection

With Calico Enterprise flow logs, you can prove to security and auditors that your policies are in place and being enforced. 

![flow-logs]({{site.baseurl}}/images/flow-logs.png)

### Audit logs

Your security team or auditor may not be satisfied with a “current point in time” compliance audit and may want to see historical data, including what changes have occurred to your policies over time.

Audit logs, when combined with flow logs, demonstrate ongoing compliance with your security requirements over time.

Calico Enterprise maintains a version history for all policy changes including what specifically changed within each policy.

![audit-logs]({{site.baseurl}}/images/audit-logs.png)

### Configuration auditing

Your security team or auditor may also ask about the configuration of your Kubernetes cluster to ensure it aligns with best-practices for security. The industry standard spec for Kubernetes security configuration is the [Center for Internet Security Benchmark for Kubernetes](https://www.cisecurity.org/benchmark/kubernetes/){:target="_blank"} (CIS).

Calico Enterprise audits the configuration of your cluster and reports on compliance and noncompliance for CIS Level 1 and Level 2 security. Configuration audits are periodically executed, enabling a historical view of the configuration over time. 

![configuration-compliance]({{site.baseurl}}/images/configuration-compliance.png)

The specific findings can be downloaded as a CSV file that provides detailed information about the current value of each configuration setting and the suggested configuration per the CIS standard. If the fix is not viable but is an acceptable risk to take within your organization, you can configure the report specification to exclude that test index so that it no longer shown in the dashboard.

### Compliance reports

Your security team or auditor will need to see that your security policies are covering all “in scope” workloads. In scope workloads are those pods that are governed by your security policy. For example, you may have some pods that are in scope for PCI compliance and others that are not.

Calico Enterprise periodically generates compliance reports that show you:

- Which endpoints are explicitly protected using ingress or egress policy
- Policies and services associated with endpoints along with policy audit logs
- Allowed ingress/egress traffic to/from namespaces and the internet

![compliance-reports]({{site.baseurl}}/images/compliance-reports.png)

A detailed spreadsheet can also be downloaded as a CSV file for every report.
