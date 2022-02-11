---
title: Calico Cloud
description: Learn about Calico Cloud.
canonical_url: '/calico-enterprise/index'
---

![calico-cloud]({{site.baseurl}}/images/calico-cloud-small.png)

## You can solve these 3 problems today...with Calico Cloud

- **Workload access controls**

    Implement pod-level workload access controls and protect containerized environments in the Kubernetes cluster from outside threats, while enabling applications and workloads to securely communicate with resources outside the cluster behind a firewall or other control point.

- **Compliance**

    Create compliance policies for any compliance framework including PCI, SOC 2, and more. Continuously monitor compliance for your container, Kubernetes, and cloud environment. Retain a daily history of your compliance status. Generate on-demand or scheduled audit reports.

- **Faster troubleshooting**

    Enable faster troubleshooting of Kubernetes workloads and applications with Service Graph, packet capture, anomaly detection, and performance hotspots, leading to shorter time-to-resolution, less application downtime, and improved quality of service.

#### Don't have a {{site.prodname}} cluster? Easy...

{% include open-new-window.html text='Try it now' url='https://www.tigera.io/tigera-products/cloud-trial' %}

#### Already have a {{site.prodname}} cluster? You are **5 minutes** away from connecting to Calico Cloud. 

1. Verify that your {% include open-new-window.html text='cluster is compatible' url='https://docs.calicocloud.io/get-started/connect/system-requirements' %}. Want to know what happens when you connect/disconnect your cluster to Calico Cloud? See {% include open-new-window.html text='Connect your cluster to Calico Cloud' url='https://docs.calicocloud.io/get-started/connect/connect-cluster' %}.

1. Identify the cluster you want to use and apply the following manifest.

   You can use any {{site.prodname}} operator-installed cluster. Ensure `kubectl` is connected to it, and then execute the following:

   ```bash
   kubectl apply -f https://installer.calicocloud.io/manifests/cc-operator/latest/deploy.yaml
   ```

1. Set your email address ($EMAIL) in the installer resource to get an invite and a license.

   ```bash

   kubectl apply -f - <<EOF
   apiVersion: operator.calicocloud.io/v1
   kind: Installer
   metadata:
     name: default
     namespace: calico-cloud
   spec:
     ownerEmail: '$EMAIL'
   EOF
   ```

1. Accept your invite to join {{site.prodname}}.

    Open the email, fill in the brief onboarding dialog, and in about 5 minutes, your cluster will open in the Calico Cloud user interface. That's it. You're ready to go!

    **Tip**: To monitor the install, run this command:

    ```bash
    kubectl get installers.operator.calicocloud.io -n calico-cloud default -o jsonpath='{.status.state}'
    ```
