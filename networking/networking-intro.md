---
title: Can you configure Calico networking?
description: Check that the Calico networking feature is available to you. 
---
Probably, but there are exceptions. Calico networking is not available if you are using Calico in the following deployments. In these cases, the Networking section is not relevant to you. 

| I am using…                                                  |
| ------------------------------------------------------------ |
| EKS or AKS as my **managed cloud provider**                  |
| A **self-managed cloud provider** (other than AWS, GCE, or Azure) |
| Flannel                                                      |
| Istio service mesh                                           |
