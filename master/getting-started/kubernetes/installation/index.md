---
title: Installing Calico on Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/'
---

We provide a number of manifests to get you up and running with {{site.prodname}} in
just a few steps. Refer to the section that corresponds to your desired networking
for instructions.

- [Installing {{site.prodname}} for policy and networking (recommended)](calico)

- [Installing {{site.prodname}} for policy and flannel for networking](flannel)

- [Installing {{site.prodname}} for policy (advanced)](other)

Should you wish to modify the manifests before applying them, refer to 
[Customizing the manifests](config-options). 

If you prefer not to use Kubernetes to start the {{site.prodname}} services, refer to the 
[Integration guide](integration).

Several third-party vendors also provide a variety of {{site.prodname}} installation
methods for different public clouds. Refer to the section that corresponds to your provider 
for more details.

- [Amazon Web Services (AWS)](aws)

- [Google Compute Engine (GCE)](gce)

- [Azure](azure)