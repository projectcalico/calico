---
title: Can you configure Calico networking?
description: Check that the Calico networking features is available to you. 
---
Can you configure Calico networking? Probably, but there are exceptions. Calico networking is not available if you are using Calico in the following deployments. In this case, the Networking section is not relevant to you. 

| I am using…                                                  |
| ------------------------------------------------------------ |
| EKS or AKS as my **managed cloud provider**                  |
| A **self-managed cloud provider** other than AWS, GCE, or Azure |
| Flannel                                                      |
| Istio service mesh                                           |
