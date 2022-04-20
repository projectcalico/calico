def gen_values(versions, imageNames, imageRegistry, chart)
  if chart == "tigera-operator"  
    versionsYml = <<~EOF
    imagePullSecrets: {}

    installation:
      enabled: true
      kubernetesProvider: ""

    apiServer:
      enabled: true

    certs:
      node:
        key:
        cert:
        commonName:
      typha:
        key:
        cert:
        commonName:
        caBundle:

    # Configuration for the tigera operator
    tigeraOperator:
      image: #{versions.fetch("tigera-operator").image}
      version: #{versions.fetch("tigera-operator").version}
      registry: #{versions.fetch("tigera-operator").registry}
    calicoctl:
      image: #{imageNames.fetch("calicoctl")}
      tag: #{versions.fetch("calicoctl")}
    EOF
  else
    versionsYml = <<~EOF
    datastore: kubernetes
    # Config for etcd
    etcd:
      # Endpoints for the etcd instances. This can be a comma separated list of endpoints.
      endpoints: null
      # Authentication information for accessing secure etcd instances.
      tls:
        crt: null
        ca: null
        key: null
    # Sets the networking mode. Can be 'calico', 'flannel', or 'none'
    network: calico
    # Sets the ipam. Can be 'calico-ipam' or 'host-local'
    ipam: calico-ipam

    # Sets the mtu.
    mtu: "1440"

    node:
      image: #{imageRegistry}#{imageNames.fetch("node")}
      tag: #{versions.fetch("calico/node")}
      env:
        # Optional environment variables for configuring Calico node.
        # These should match the EnvVar spec of the corev1 Kubernetes API. For example:
        # - name: FELIX_LOGSEVERITYSCREEN
        #   value: "debug"
    calicoctl:
      image: #{imageRegistry}#{imageNames.fetch("calicoctl")}
      tag: #{versions.fetch("calicoctl")}
    typha:
      image: #{imageRegistry}#{imageNames.fetch("typha")}
      tag: #{versions.fetch("typha")}
      env:
        # Optional environment variables for configuring Typha.
        # These should match the EnvVar spec of the corev1 Kubernetes API. For example:
        # - name: TYPHA_LOGSEVERITYSYS
        #   value: debug
    cni:
      image: #{imageRegistry}#{imageNames.fetch("cni")}
      tag: #{versions.fetch("calico/cni")}
      env:
        # Optional environment variables for configuring Calico CNI.
        # These should match the EnvVar spec of the corev1 Kubernetes API. For example:
        # - name: FOO
        #   value: bar
    kubeControllers:
      image: #{imageRegistry}#{imageNames.fetch("kubeControllers")}
      tag: #{versions.fetch("calico/kube-controllers")}
      env:
        # Optional environment variables for configuring Calico kube controllers.
        # These should match the EnvVar spec of the corev1 Kubernetes API. For example:
        # - name: LOG_LEVEL
        #   value: debug
    flannel:
      image: #{imageNames.fetch("flannel")}
      tag: #{versions.fetch("flannel")}
      env:
        # Optional environment variables for configuring Flannel.
        # These should match the EnvVar spec of the corev1 Kubernetes API. For example:
        # - name: FOO
        #   value: bar
    flannelMigration:
      image: #{imageNames.fetch("flannelMigration")}
      tag: #{versions.fetch("calico/kube-controllers")}
    dikastes:
      image: #{imageRegistry}#{imageNames.fetch("dikastes")}
      tag: #{versions.fetch("calico/dikastes")}
    flexvol:
      image: #{imageRegistry}#{imageNames.fetch("flexvol")}
      tag: #{versions.fetch("flexvol")}
    csi-driver:
      image: #{imageRegistry}#{imageNames.fetch("csi-driver")}
      tag: #{versions.fetch("csi-driver")}

    EOF
  end
end
