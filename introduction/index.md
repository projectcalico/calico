---
title: About Calico
show_title: false
canonical_url: '/introduction/index'
custom_css: css/intro.css
---

<div id="why-use-calico-1" class="row">
  <div class="col-md-6">
    <img style="max-width: 330px" class="img-responsive center-block" src="/images/felix_icon.png">
  </div>
  <div class="col-md-6">
    <h3 style="margin-top: 5px">What is {{site.prodname}}?</h3>
    <p>{{site.prodname}} is an open source networking and network security solution for containers, virtual machines, and native host-based workloads. {{site.prodname}} supports a broad range of platforms including Kubernetes, OpenShift, Docker EE, OpenStack, and bare metal services.</p>
    <p>{{site.prodname}} combines flexible networking capabilities with run-anywhere security enforcement to provide a solution with native Linux kernel performance and true cloud-native scalability. {{site.prodname}} provides developers and cluster operators with a consistent experience and set of capabilities whether running in public cloud or on-prem, on a single node or across a multi-thousand node cluster.</p>
  </div>
</div>

<hr/>

<div style="text-align: center">
  <h2>Why use {{site.prodname}}?</h2>
</div>

<hr/>

<div id="why-use-calico-2" class="row">
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Best practices for network security</h3>
    <p>{{site.prodname}}’s rich network policy model makes it easy to lock down communication so the only traffic that flows is the traffic you want to flow. You can think of {{site.prodname}}’s security enforcement as wrapping each of your workloads with its own personal firewall that is dynamically re-configured in real time as you deploy new services or scale your application up or down.</p>
    <p>{{site.prodname}}’s policy engine can enforce the same policy model at the host networking layer and (if using Istio & Envoy) at the service mesh layer, protecting your infrastructure from compromised workloads and protecting your workloads from compromised infrastructure.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/best-practices.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-3" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/performance.png">
  </div>
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Performance</h3>
    <p>{{site.prodname}} uses the Linux kernel’s built-in highly optimized forwarding and access control capabilities to deliver native Linux networking dataplane performance, typically without requiring any of the encap/decap overheads associated with first generation SDN networks. {{site.prodname}}’s control plane and policy engine has been fine tuned over many years of production use to minimize overall CPU usage and occupancy.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-4" class="row">
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Scalability</h3>
    <p>{{site.prodname}}’s core design principles leverage best practice cloud-native design patterns combined with proven standards based network protocols trusted worldwide by the largest internet carriers. The result is a solution with exceptional scalability that has been running at scale in production for years. {{site.prodname}}’s development test cycle includes regularly testing multi-thousand node clusters.  Whether you are running a 10 node cluster, 100 node cluster, or more, you reap the benefits of the improved performance and scalability characteristics demanded by the largest Kubernetes clusters.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/scale.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-5" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/interoperability.png">
  </div>
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Interoperability</h3>
    <p>{{site.prodname}} enables Kubernetes workloads and non-Kubernetes or legacy workloads to communicate seamlessly and securely.  Kubernetes pods are first class citizens on your network and able to communicate with any other workload on your network.  In addition {{site.prodname}} can seamlessly extend to secure your existing host based workloads (whether in public cloud or on-prem on VMs or bare metal servers) alongside Kubernetes.  All workloads are subject to the same network policy model so the only traffic that is allowed to flow is the traffic you expect to flow.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-6" class="row">
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Looks familiar</h3>
    <p>{{site.prodname}} uses the Linux primitives that existing system administrators are already familiar with. Type in your favorite Linux networking command and you’ll get the results you expect.  In the vast majority of deployments the packet leaving your application is the packet that goes on the wire, with no encapsulation, tunnels, or overlays.  All the existings tools that system and network administrators use to gain visibility and analyze networking issues work as they do today.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/looks-familiar.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-7" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/deployed.png">
  </div>
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Real world production hardened</h3>
    <p>{{site.prodname}} is trusted and running in production at large enterprises including SaaS providers, financial services companies, and manufacturers.  The largest public cloud providers have selected {{site.prodname}} to provide network security for their hosted Kubernetes services (Amazon EKS, Azure AKS, Google GKE, and IBM IKS) running across tens of thousands of clusters.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-8" class="row">
  <div class="col-md-6">
    <h3 style="margin-top: 5px">Full Kubernetes network policy support</h3>
    <p>{{site.prodname}}’s network policy engine formed the original reference implementation of Kubernetes network policy during the development of the API. {{site.prodname}} is distinguished in that it implements the full set of features defined by the API giving users all the capabilities and flexibility envisaged when the API was defined. And for users that require even more power, {{site.prodname}} supports an extended set of network policy capabilities that work seamlessly alongside the Kubernetes API giving users even more flexibility in how they define their network policies.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/policy.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-9" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="/images/intro/tigera.png">
  </div>
  <div class="col-md-6">
    <h3 style="margin-top: 5px">A contributor community backed by the Tigera team</h3>
    <p>The {{site.prodname}} open source project has been supported by 150+ contributors across a broad range of companies.  In addition {{site.prodname}} is backed by Tigera, founded by the original {{site.prodname}} engineering team, and committed to maintaining {{site.prodname}} as the leading standard for Kubernetes network security.</p>
  </div>
</div>
