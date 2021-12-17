This directory contains example scripts for starting kubelet and kube-proxy in a way
that works with Calico For Windows.

The scripts assume that:

- kube-proxy.exe and kubelet.exe are installed to c:\k\.
- The HNS network name is "Calico".

The install-kube-services script:

- Install kubelet and kube-proxy service.

The uninstall-kube-services script:

- Uninstall kubelet and kube-proxy service.

The kubelet-service script:

- Forces kubelet to use the node name configured in the Calico configuration file.
- Explicitly sets the node IP (we have seen kubelet sometimes detect the IP of the
  NAT interface instead of the main ethernet interface).

The kube-proxy-service script:

- Forces kube-proxy to use the node name configured in the Calico configuration file.
- Enables the WinDSR and WinOverlay feature flags (for kube-proxy >=1.14).

  - The WinDSR flag is required for Kubernetes service ClusterIPs to
    work correctly with Calico policy.  Without that flag, kube-proxy
    performs SNAT for all ClusterIPs resulting in Calico policy seeing the
    wrong source address.

    WinDSR also requires a compatible version of Windows.  At the time of writing,
    Windows 19H1 build 18317 or later was required.  (The current build of Windows
    1809 / Server 2019 does not support DSR.)

  - The WinOverlay flag is required to enable VXLAN support.  This also requires
    a compatible build of Windows.

