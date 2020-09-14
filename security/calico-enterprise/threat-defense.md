---
title: Threat defense
description: Detect, alert, and block advanced persistent threats and active attacks against your applications.
calico_enterprise: true
---

For Kubernetes deployments, Calico Enterprise gives you advanced threat defense capabilities that can detect, alert, and block advanced persistent threats and active attacks against your applications.

### Threat intelligence feeds

Threat intelligence feeds are real-time streams of data that provide information on potential cyber threats and risks. Calico Enterprise integrates threat feeds into Calico policies that can alert or block ingress and egress to/from known bad actors based on data within the feed. Calico Enterprise comes packaged with a free, open-source threat feed, but you can also import data from any threat feed your security team uses.

![threat-feed]({{site.baseurl}}/images/threat-feed.png)

### Anomaly detection

Calico Enterprise detects suspicious network traffic within your cluster and can alert or take action. Calico Enterprise anomaly detection uses two methods to identify suspicious traffic:

- Detecting known attack vectors such as port scans and IP sweeps
- Baselining network behaviour and alerting on deviance from that behavior

When suspicious traffic is detected, Calico Enterprise can be aligned or integrated into your security team’s workflow to resolve the issue. Common examples are isolating the pod from the network or sending an alert to your security team’s Security Incident and Event Management (SIEM) system such as Splunk or Sumo for further investigation by your security operations center.

![anomaly-detection]({{site.baseurl}}/images/anomaly-detection.png)

### Domain generation algorithm detection

Advanced Persistent Threats (APTs) are becoming more complex, long-lived, and harder to identify. Some advanced malware avoids detection and skirts threat feeds by using [Domain Generation Algorithms](https://en.wikipedia.org/wiki/Domain_generation_algorithm){:target="_blank"}.

Calico Enterprise monitors egress traffic and uses machine learning to identify DGA patterns, helping you and your security team to isolate those workloads from the network to eliminate the threat.

![dga-detection]({{site.baseurl}}/images/dga-detection.png)

### Custom alerts

You can configure Calico Enterprise with custom alerts to cover many scenarios that may required by your security teams:

- Changes to the security policies you defined
- User RBAC changes
- Known hijacking methods

Calico Enterprise is backed by Tigera, who employ a team of threat researchers that regularly publish blogs and webinars about known attack vectors and publish custom alerts for Calico Enterprise to detect and alert on the latest intrusion and exfiltration techniques. Calico Enterprise also offers a web interface that your own threat researchers and security engineers can use to define their own rules and alerts.
