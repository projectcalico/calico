---
title: Try out the eBPF tech preview
description: Try out the eBPF dataplane tech preview.
---

### Big picture

Install {{site.prodname}} and enable the tech preview of the new eBPF dataplane.

> **Warning!** eBPF mode is a tech preview and should not be used in production clusters. It has had very limited testing and it will contain bugs such as dropping packets or slowing down responses (please report these on the Calico Users slack or Github).  In addition, it does not support all the features of {{site.prodname}} and it is missing some security features (for example anti-spoofing protection).
{: .alert .alert-danger }

### Value

The new eBPF dataplane mode has several advantages over standard linux networking pipeline mode:

* It scales to higher throughput.
* It uses less CPU per GBit.
* It has native support for Kubernetes services (without needing kube-proxy) that:

  * Reduces first packet latency for packets to services.
  * Preserves external client source IP addresses all the way to the pod.
  * Supports DSR (Direct Server Return) for more efficient service routing.
  * Uses less CPU than kube-proxy to keep the dataplane in sync.
  
Trying out the tech preview will give you a taste of these benefits and an opportunity to give feedback to the {{site.prodname}} team. 

To learn more and see performance metrics from our test environment, see the blog, {% include open-new-window.html text='Introducing the Calico eBPF dataplane' url='https://www.projectcalico.org/introducing-the-calico-ebpf-dataplane/' %}.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **calico/node**
- **eBPF dataplane**

### Concepts

#### eBPF

eBPF (or "extended Berkeley Packet Filter"), is a technology that allows you to write mini programs that can be attached to various low-level hooks in the Linux kernel, for a wide variety of uses including networking, security, and tracing. You’ll see a lot of non-networking projects leveraging eBPF, but for {{site.prodname}} our focus is on networking, and in particular, pushing the networking capabilities of the latest Linux kernels to the limit.

#### eBPF mode manifest

To make it easier to try out the tech preview, we have created a custom Kubernetes manifest (.yaml file) with eBPF mode pre-enabled.

### Before you begin...

In the tech preview release, eBPF mode has the following pre-requisites:

- A v5.3+ Linux kernel, for the tech preview release, we have limited our testing to Ubuntu 19.10 so we strongly recommend that you start with that too.
- An underlying network that doesn't require Calico to use an overlay.  The instructions below guide you through setting up a cluster in a single AWS subnet; an alternative would be to set up your cluster on-prem with a routed network topology.
- The network must be configured to allow VXLAN packets between  {{site.prodname}}  hosts.
- Single-homed hosts; eBPF mode currently assumes a single "main" host IP and interface.
- Must use the Calico CNI plugin and Calico IPAM.  It is not yet compatible with third-party CNI plugins (AWS CNI/Azure CNI/GKE CNI/flannel etc).
- IPv4 only.  The tech preview release does not support IPv6.
- The MTU used by the BPF programs when doing encapsulation is hard coded (with the inner MTU limited to 1410 bytes).
- Kubernetes API Datastore only.
- Typha is not supported in the tech preview. 
- The base [requirements]({{site.baseurl}}/getting-started/kubernetes/requirements) also apply.

### How to

- [Set up a suitable cluster](#set-up-a-suitable-cluster)
- [Install Calico on nodes](#install-calico-on-nodes)
- [Toggle between eBPF and the standard linux networking pipeline](#toggle-between-ebpf-and-the-standard-linux-networking-pipeline)

#### Set up a suitable cluster

We recommend using `kubeadm` to bootstrap a suitable cluster on AWS.  

1. In AWS, create a controller node and at least 2 worker nodes in the same VPC subnet.  Use Ubuntu 19.10 as the image.

1. **Important** disable the source/destination check on each node's interface.  This is required in order to use non-overlay networking.

   1. Open the Amazon EC2 console and navigate to "Instances".

   1. Select the instance and choose **Actions** > **Networking** > **Change Source/Dest. Check**.

   1. Verify that source/destination check is disabled. Otherwise, choose **Yes, Disable**.

1. On each node, {% include open-new-window.html text='install kubeadm' url='https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/' %}; we recommend using docker as the container runtime in order to match our test environment as closely as possible.

1. Create the controller node of a new cluster. On the controller VM, execute:

   ```
   sudo kubeadm init --pod-network-cidr 192.168.0.0/16
   ```

1. To set up kubectl for the ubuntu user, run:

   ```
   mkdir -p $HOME/.kube
   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
   sudo chown $(id -u):$(id -g) $HOME/.kube/config
   ```
   The final line of the kubeadm init output contains the command for joining your workers to the controller.  Run this on each worker, prepending `sudo` to run it as root.  It will look something like this:

   ```
   sudo kubeadm join 10.240.0.11:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>
   ```

1. On the controller, verify that all nodes have joined

   ```
   kubectl get nodes
   ```
   which should output something similar to:

   ```
   NAME                                           STATUS      ROLES    AGE   VERSION
   ip-172-16-101-119.us-west-2.compute.internal   NotReady    <none>   86m   v1.17.3
   ip-172-16-101-27.us-west-2.compute.internal    NotReady    <none>   86m   v1.17.3
   ip-172-16-101-49.us-west-2.compute.internal    NotReady    master   88m   v1.17.3
   ip-172-16-102-174.us-west-2.compute.internal   NotReady    <none>   86m   v1.17.3
   ```

   The nodes will report `NotReady` until we complete the installation of {{site.prodname}} below.

#### Install {{site.prodname}} on nodes

For the tech preview, only the Kubernetes API Datastore is supported.  Since {{site.prodname}} replaces `kube-proxy` in eBPF mode, it requires the IP and port of your API server to be set in its config map. 

1. Download the following {{site.prodname}} install manifest.

   ```bash
   curl {{ "/manifests/calico-bpf.yaml" | absolute_url }} -O
   ```
   
   The manifest is configured to:
    
   * use the Kubernetes API Datastore
   * turn on BPF mode
   * use no encapsulation (which requires using a single subnet in AWS).
   
1. Find the real IP and port of your API server.  One way to do this is to run the following command:
   ```bash
   kubectl get endpoints kubernetes
   ```
   The output should look like this:
   ```bash
   kubectl get endpoints kubernetes
   NAME         ENDPOINTS           AGE
   kubernetes   <IP>:<port>         43h
   ```
   Record the `<IP>` and `<port>`.
1. Modify the `kubernetes_service_host` and `kubernetes_service_port` variables in the config map at the top of the manifest.  Set `kubernetes_service_host` to the IP you recorded above.  Set `kubernetes_service_port` to the port.
   ```yaml
   kind: ConfigMap
   apiVersion: v1
   metadata:
     name: calico-config
     namespace: kube-system
   data:
     ...
     kubernetes_service_host: "<IP>"
     kubernetes_service_port: "<port>"
     ...
   ```
   
1. Disable `kube-proxy` on your cluster.  The following command adds a node selector to the `kube-proxy` daemon set that won't match anything:

   ```bash
   kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
   ```  
   
   Since the selector won't match anything, `kube-proxy` won't run anywhere but it can be easily re-enabled by removing the selector.
   
1. Apply the {{site.prodname}} manifest using the following command.

   ```bash
   kubectl apply -f calico-bpf.yaml
   ```
   
1. Verify that the calico-node pods start and become ready and that the `kube-proxy` pods shut down:
   ```bash
   watch kubectl get po -n kube-system
   ```
   Should give output like this:
   ```
   NAME                                            READY   STATUS    RESTARTS   AGE
   calico-kube-controllers-78d64db6fd-dlqwm        1/1     Running   0          28m
   calico-node-6ffzz                               1/1     Running   0          13m
   calico-node-9ccpx                               1/1     Running   0          13m
   calico-node-mx2v4                               1/1     Running   0          13m
   calico-node-n9pc9                               1/1     Running   0          13m
   coredns-5644d7b6d9-bpddg                        1/1     Running   0          46m
   coredns-5644d7b6d9-glfr7                        1/1     Running   0          46m
   etcd-host-name                                  1/1     Running   0          46m
   kube-apiserver-host-name                        1/1     Running   0          46m
   kube-controller-manager-host-name               1/1     Running   0          46m
   kube-scheduler-host-name                        1/1     Running   0          46m
   ``` 

#### Toggle between eBPF and the standard linux networking pipeline 

After following the above instructions you'll have a cluster running in eBPF mode.  If you'd like to switch to the standard linux networking pipeline mode for comparison purposes:

1. In the manifest above, eBPF mode is configured with an environment variable.  To disable it, you can patch the calico-node daemon set:
   ```bash
   kubectl set env -n kube-system ds/calico-node FELIX_BPFENABLED="false"
   ```
   
1. To re-enable the Kubernetes `kube-proxy` you can use the following command to reverse the node selector change we made above:
   ```bash
   kubectl patch ds -n kube-system kube-proxy --type merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": null}}}}}'
   ```

To re-enable BPF mode:

1. Disable `kube-proxy` on your cluster.  The following command adds a node selector to the `kube-proxy` daemon set that won't match anything:

   ```bash
   kubectl patch ds -n kube-system kube-proxy -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
   ```  
   
1. Re-enable eBPF mode:
   ```bash
   kubectl set env -n kube-system ds/calico-node FELIX_BPFENABLED="true"
   ```

> **Warning!** Switching between eBPF and standard linux networking can cause long-lived flows to be silently dropped since the two dataplane modes do not share connection-tracking state.
{: .alert .alert-danger }

### Send us feedback

We want to hear about your experience, so please don’t hesitate to connect with us via the {% include open-new-window.html text='Calico Users Slack' url='http://slack.projectcalico.org/' %} group.
