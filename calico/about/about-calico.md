---
title: About Calico
description: The value of using Calico for networking and network security for workloads and hosts.
show_title: false
canonical_url: '/about/about-calico'
custom_css: css/intro.css
---

<div id="why-use-calico-1" class="row">
  <div class="col-md-6">
    <img style="max-width: 330px" class="img-responsive center-block" src="{{ site.baseurl }}/images/felix_icon.png">
  </div>
  <div class="col-md-6">
    <h3 id="what-is" style="margin-top: 5px">What is {{site.prodname}}?</h3>
    <p>{{site.prodname}} is an open source networking and network security solution for containers, virtual machines, and native host-based workloads. {{site.prodname}} supports a broad range of platforms including Kubernetes, OpenShift, Mirantis Kubernetes Engine (MKE), OpenStack, and bare metal services.</p>
    <p>Whether you opt to use {{site.prodname}}'s eBPF data plane or Linux’s standard networking pipeline, {{site.prodname}} delivers blazing fast performance with true cloud-native scalability. {{site.prodname}} provides developers and cluster operators with a consistent experience and set of capabilities whether running in public cloud or on-prem, on a single node, or across a multi-thousand node cluster.</p>
  </div>
</div>

<hr/>

<div style="text-align: center">
  <h2 id="why-use">Why use {{site.prodname}}?</h2>
</div>

<hr/>

<div id="why-use-calico-6" class="row">
  <div class="col-md-6">
    <h3 id="familiar" style="margin-top: 5px">Choice of dataplanes</h3>
    <p>{{site.prodname}} gives you a choice of dataplanes, including a pure Linux eBPF dataplane, a standard Linux networking dataplane, and a Windows HNS dataplane. Whether you prefer cutting edge features of eBPF, or the familiarity of the standard primitives that existing system administrators already know, Calico has you covered.</p>
    <p>Whichever choice is right for you, you’ll get the same, easy to use, base networking, network policy and IP address management capabilities, that have made Calico the most trusted networking and network policy solution for mission-critical cloud-native applications.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/multiple-dataplanes.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-2" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/best-practices.png">
  </div>
  <div class="col-md-6">
    <h3 id="best-practices" style="margin-top: 5px">Best practices for network security</h3>
    <p>{{site.prodname}}’s rich network policy model makes it easy to lock down communication so the only traffic that flows is the traffic you want to flow. Plus with built in support for Wireguard encryption, securing your pod-to-pod traffic across the network has never been easier.</p>

    <p>{{site.prodname}}’s policy engine can enforce the same policy model at the host networking layer and (if using Istio & Envoy) at the service mesh layer, protecting your infrastructure from compromised workloads and protecting your workloads from compromised infrastructure.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-3" class="row">
  <div class="col-md-6">
    <h3 id="performance" style="margin-top: 5px">Performance</h3>
    <p>Depending on your preference, {{site.prodname}} uses either Linux eBPF or the Linux kernel's highly optimized standard networking pipeline to deliver high performance networking. {{site.prodname}}'s networking options are flexible enough to run without using overlays in most environments, avoiding the overheads of packet encap/decap. {{site.prodname}}’s control plane and policy engine has been fine tuned over many years of production use to minimize overall CPU usage and occupancy.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/performance.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-4" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/scale.png">
  </div>
  <div class="col-md-6">
    <h3 id="scalability" style="margin-top: 5px">Scalability</h3>
    <p>{{site.prodname}}’s core design principles leverage best practice cloud-native design patterns combined with proven standards based network protocols trusted worldwide by the largest internet carriers. The result is a solution with exceptional scalability that has been running at scale in production for years. {{site.prodname}}’s development test cycle includes regularly testing multi-thousand node clusters.  Whether you are running a 10 node cluster, 100 node cluster, or more, you reap the benefits of the improved performance and scalability characteristics demanded by the largest Kubernetes clusters.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-5" class="row">
  <div class="col-md-6">
    <h3 id="interoperability" style="margin-top: 5px">Interoperability</h3>
    <p>{{site.prodname}} enables Kubernetes workloads and non-Kubernetes or legacy workloads to communicate seamlessly and securely.  Kubernetes pods are first class citizens on your network and able to communicate with any other workload on your network.  In addition {{site.prodname}} can seamlessly extend to secure your existing host based workloads (whether in public cloud or on-prem on VMs or bare metal servers) alongside Kubernetes.  All workloads are subject to the same network policy model so the only traffic that is allowed to flow is the traffic you expect to flow.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/interoperability.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-7" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/deployed.png">
  </div>
  <div class="col-md-6">
    <h3 id="real-world-production" style="margin-top: 5px">Real world production hardened</h3>
    <p>{{site.prodname}} is trusted and running in production at large enterprises including SaaS providers, financial services companies, and manufacturers.  The largest public cloud providers have selected {{site.prodname}} to provide network security for their hosted Kubernetes services (Amazon EKS, Azure AKS, Google GKE, and IBM IKS) running across tens of thousands of clusters.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-8" class="row">
  <div class="col-md-6">
    <h3 id="full-kubernetes-support" style="margin-top: 5px">Full Kubernetes network policy support</h3>
    <p>{{site.prodname}}’s network policy engine formed the original reference implementation of Kubernetes network policy during the development of the API. {{site.prodname}} is distinguished in that it implements the full set of features defined by the API giving users all the capabilities and flexibility envisaged when the API was defined. And for users that require even more power, {{site.prodname}} supports an extended set of network policy capabilities that work seamlessly alongside the Kubernetes API giving users even more flexibility in how they define their network policies.</p>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/policy.png">
  </div>
</div>

<hr/>

<div id="why-use-calico-9" class="row">
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/intro/community.png">
  </div>
  <div class="col-md-6">
    <h3 id="contributor-community" style="margin-top: 5px">Contributor community</h3>
    <p>The Calico open source project is what it is today thanks to 200+ contributors across a broad range of companies.  In addition {{site.prodname}} is backed by Tigera, founded by the original Calico engineering team, and committed to maintaining {{site.prodname}} as the leading standard for Kubernetes network security.</p>
  </div>
</div>

<hr/>

<div id="why-use-calico-10" class="row">
  <div class="col-md-6">
    <h3 id="enterprise-compatible" style="margin-top: 5px">Calico Cloud compatible</h3>
    <p>Calico Cloud builds on top of open source Calico to provide Kubernetes security and observability features and capabilities:</p>
    <ul style="">
        <li>Egress access controls (DNS policies, egress gateways)</li>
        <li>Extend firewall to Kubernetes</li>
        <li>Hierarchical tiers</li>
        <li>FQDN / DNS based policy</li>
        <li>Micro-segmentation across host/VMs/containers</li>
        <li>Security policy preview, staging, and recommendation</li>
        <li>Compliance reporting and alerts</li>
        <li>Intrusion detection & prevention (IDS / IPS) for Kubernetes</li>
        <li>SIEM Integrations</li>
        <li>Application Layer (L7) observability</li>
        <li>Dynamic packet capture</li>
        <li>DNS dashboards</li>
    </ul>
  </div>
  <div class="col-md-6">
    <img class="img-responsive center-block" src="{{ site.baseurl }}/images/calico-cloud-small.png">
    <div style="display: flex; justify-content: center; align-items: center;" id="enterprise-footer">
      <a href="https://www.tigera.io/tigera-products/calico-cloud/" class="learn-more-button">Learn More</a>
    </div>    
  </div>
</div>




