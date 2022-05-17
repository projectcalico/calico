The eBPF dataplane mode has several advantages over standard Linux networking pipeline mode:

* It scales to higher throughput.
* It uses less CPU per GBit.
* It has native support for Kubernetes services (without needing kube-proxy) that:

    * Reduces first packet latency for packets to services.
    * Preserves external client source IP addresses all the way to the pod.
    * Supports DSR (Direct Server Return) for more efficient service routing.
    * Uses less CPU than kube-proxy to keep the dataplane in sync.

To learn more and see performance metrics from our test environment, see the blog, {% include open-new-window.html text='Introducing the Calico eBPF dataplane' url='https://www.projectcalico.org/introducing-the-calico-ebpf-dataplane/' %}.
