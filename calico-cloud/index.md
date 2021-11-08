---
title: Calico Cloud
description: Learn about Calico Cloud.
canonical_url: '/calico-cloud/index'
---

![calico-cloud]({{site.baseurl}}/images/calico-cloud-small.png)

## If you could solve these 3 problems today...

  #### Workload access controls

  Implement pod-level workload access controls and protect containerized environments in the Kubernetes cluster from outside threats, while enabling applications and workloads to securely communicate with resources outside the cluster behind a firewall or other control point.

  #### Compliance

  Create compliance policies for any compliance framework including PCI, SOC 2, and more. Continuously monitor compliance for your container, Kubernetes, and cloud environment. Retain a daily history of your compliance status. Generate on-demand or scheduled audit reports.

  #### Faster troubleshooting

  Enable faster troubleshooting of Kubernetes workloads and applications with Service Graph, Packet Capture, anomaly detection, and performance hotspots, leading to shorter time-to-resolution, less application downtime, and improved quality of service

## then take your cluster into Calico Cloud and see for yourself!
   
### Don't have a Calico cluster? Easy...<a href="https://www.tigera.io/tigera-products/cloud-trial" class="request-demo-button" target="_blank" rel="noopener noreferreer">Try it now!</a>


### Already have a Calico cluster? You are **~5 minutes** away from connection!

1. Identify the cluster you want to use and apply the following manifest.

    You can use any Calico operator-installed cluster that is configure with `kubectl`.

   ```bash
   kubectl apply -f https://storage.googleapis.com/dev-calicocloud-installer/manifests/cc-operator/latest/deploy.yaml
   ```
1. Add your email address to get an invite and a license.

   ```bash
   kubectl apply -f https://storage.googleapis.com/dev-calicocloud-installer/manifests/cc-operator/latest/deploy.yaml
   ```  
1. Accept your invite to join {{site.prodname}}.

    Open the email, fill in the brief onboarding dialog, and in about 5 minutes, your cluster will appear in the Calico Cloud Manager UI drop-down menu. That's it! You're ready to go! 

    **Can I disconnect my cluster at any time?** Yes. Whether you’ve finished with your {{site.prodname}} Trial or decided to disconnect your cluster earlier, we know you want your cluster to remain functional. We have a doc with steps to run a simple script to {% include open-new-window.html text='migrate your cluster back to open-source Project Calico' url='https://docs.calicocloud.io/operations/disconnect' %}.
    


