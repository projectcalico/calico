def gen_values_v3_7(versions, imageNames, imageRegistry)
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
    app_layer_policy: false

    node:
      image: #{imageRegistry}#{imageNames["node"]}
      tag: #{versions["calico/node"]}
    calicoctl:
      image: #{imageRegistry}#{imageNames["calicoctl"]}
      tag: #{versions["calicoctl"]}
    typha:
      image: #{imageRegistry}#{imageNames["typha"]}
      tag: #{versions["typha"]}
    cni:
      image: #{imageRegistry}#{imageNames["cni"]}
      tag: #{versions["calico/cni"]}
    kubeControllers:
      image: #{imageRegistry}#{imageNames["kubeControllers"]}
      tag: #{versions["calico/kube-controllers"]}
    flannel:
      image: #{imageNames["flannel"]}
      tag: #{versions["flannel"]}
    dikastes:
      image: #{imageRegistry}#{imageNames["dikastes"]}
      tag: #{versions["calico/dikastes"]}
    flexvol:
      image: #{imageRegistry}#{imageNames["flexvol"]}
      tag: #{versions["flexvol"]}
    EOF
end
