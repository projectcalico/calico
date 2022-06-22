{%- if include.networkingType == "vxlan" %}
1. Ensure that BGP is disabled.
   - If you installed {{site.prodname}} using the manifest, BGP is already disabled.
   - If you installed {{site.prodname}} using the operator, run this command:

   ```bash
   kubectl patch installation default --type=merge -p '{"spec": {"calicoNetwork": {"bgp": "Disabled"}}}'
   ```
{%- else %}
1. Enable BGP service on the Windows nodes.
   Install the RemoteAccess service using the following Powershell commands:

   ```powershell
   Install-WindowsFeature RemoteAccess
   Install-WindowsFeature RSAT-RemoteAccess-PowerShell
   Install-WindowsFeature Routing
   ```

   Then restart the computer:

   ```powershell
   Restart-Computer -Force
   ```

   before running:

   ```powershell
   Install-RemoteAccess -VpnType RoutingOnly
   ```
   Sometimes the remote access service fails to start automatically after install. To make sure it is running, run the following command:

   ```powershell
   Start-Service RemoteAccess
   ```
{%- endif %}

1. Download the {{site.prodnameWindows}} installation manifest.

   ```bash
{%- if include.networkingType == "vxlan" %}
   curl {{site.data.versions.first.manifests_url}}/manifests/calico-windows-vxlan.yaml -o calico-windows.yaml
{%- else %}
   curl {{site.data.versions.first.manifests_url}}/manifests/calico-windows-bgp.yaml -o calico-windows.yaml
{%- endif %}
   ```

1. Get the cluster's Kubernetes API server host and port, which will be used to update the {{site.prodnameWindows}} config map.
   The API server host and port is required so that the {{site.prodnameWindows}} installation script can create a kubeconfig file for {{site.prodname}} services.
   If your Windows nodes already have {{site.prodnameWindows}} installed manually, skip this step. The installation script will
   use the API server host and port from your node's existing kubeconfig file if the `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` variables
   are not provided in the `calico-windows-config` ConfigMap.

   {% include content/kube-apiserver-host-port.md %}

1. Edit the `calico-windows-config` ConfigMap in the downloaded manifest and ensure the required variables are correct for your cluster.
{%- if include.networkingType == "vxlan" %}
   - `CALICO_NETWORKING_BACKEND`: This should be set to **vxlan**.
{%- else %}
   - `CALICO_NETWORKING_BACKEND`: This should be set to **windows-bgp**.
{%- endif %}
   - `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`: The Kubernetes API server host and port (discovered in the previous step) used to create a kubeconfig file for {{site.prodname}} services. If your node already has an existing kubeconfig file, leave these variables blank.
   - `K8S_SERVICE_CIDR`: The Kubernetes service clusterIP range configured in your cluster. This must match the service-cluster-ip-range used by kube-apiserver.
   - `CNI_BIN_DIR`: Path where {{site.prodname}} CNI binaries will be installed. This must match the CNI bin value in the ContainerD service configuration. If you used the provided Install-Containerd.ps1 script, you should use the CNI bin path value you provided to that script.
   - `CNI_CONF_DIR`: Path where {{site.prodname}} CNI configuration will be installed. This must match the CNI conf value in the ContainerD service configuration. If you used the provided Install-Containerd.ps1 script, you should use the CNI conf path value you provided to that script.
   - `DNS_NAME_SERVERS`: The DNS nameservers that will be used in the CNI configuration.
   - `FELIX_HEALTHENABLED`: The Felix health check server must be enabled.

1. Apply the {{site.prodnameWindows}} installation manifest.

   ```bash
   kubectl create -f calico-windows.yaml
   ```

1. Monitor the installation.

   ```bash
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c install
   ```

   After the log `Calico for Windows installed` appears, installation is complete.
   Next, the {{site.prodnameWindows}} services are started in separate containers:

   ```bash
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c node
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c felix
{%- if include.networkingType == "windows-bgp" %}
   kubectl logs -f -n calico-system -l k8s-app=calico-node-windows -c confd
{%- endif %}
   ```

1. Install kube-proxy.

   Depending on your platform, you may already have kube-proxy running on your Windows nodes.
   If kube-proxy is already running on your Windows nodes, skip this step. If kube-proxy is not running,
   you must install and run kube-proxy on each of the Windows nodes in your cluster.
   Note: The provided manifest depends on the kubeconfig provided by the `kube-proxy` ConfigMap in the `kube-system` namespace.

   - Download the kube-proxy manifest:
   ```bash
   curl {{site.data.versions.first.manifests_url}}/manifests/windows-kube-proxy.yaml -o windows-kube-proxy.yaml
   ```
   - Edit the downloaded manifest
       - Replace `VERSION` with your Windows nodes' server version. E.g. `1809`.
       - Update the `K8S_VERSION` env variable value with your Kubernetes cluster version.

   - Apply the manifest
   ```bash
   kubectl apply -f windows-kube-proxy.yaml
   ```

   - Verify the kube-proxy-windows daemonset is running
   ```bash
   kubectl describe ds -n kube-system kube-proxy-windows
   ```
