---
title: Advanced compliance controls with Calico Enterprise
description: Calico Enterprise provides complex security controls required by security teams.
calico_enterprise: true
---

Calico policies can be used to implement security controls required by your security team. Some security controls are simple, such as separating development and test workloads or segmenting a cluster into security zones (DMZ, Trusted, etc.) or could be more complex like implementing HIPAA or PCI-DSS controls.

For most security teams, setting up and enforcing Calico Policy is not sufficient to meet their needs.
Security teams need additional controls to ensure their policies have precedence and are evaluated first before other policies
They need to see proof that the controls are in place, being enforced, and working as expected (logs, evidence reports, audit history)

Calico Enterprise adds several features that satisfy the security team’s requirements.

### Tiered policies

- Enable separation of duties
- Define cluster-wide policies that cannot be overridden 
- Tiers are evaluated left to right, top to bottom

![tiered-policies]({{site.baseurl}}/images/tiered-policies.png)

### Flow logs

- Auditors need proof that security controls are and have been enforced
- Data in flow log
- Screenshot

### Audit logs

- Marry audit log with flow logs to demonstrate adherence
- Includes change history

### Configuration auditing

- CIS Benchmark Level 1 and Level 2
- Periodically reports. Can download report from any historical point in time
- Screenshot

### Evidence reports

- Evidence reports show you which pods are covered by policies
- Screenshots of reports
- Download and share with auditor

![compliance-reports]({{site.baseurl}}/images/compliance-reports.png)
