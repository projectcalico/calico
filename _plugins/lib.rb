def gen_values(versions, imageNames, version, imageRegistry)
    components = versions[version][0]["components"]
    versionsYml = <<~EOF
    node:
      image: #{imageRegistry}#{imageNames["node"]}
      tag: #{components["calico/node"]["version"]}
    calicoctl:
      image: #{imageRegistry}#{imageNames["calicoctl"]}
      tag: #{components["calicoctl"]["version"]}
    typha:
      image: #{imageRegistry}#{imageNames["typha"]}
      tag: #{components["typha"]["version"]}
    cni:
      image: #{imageRegistry}#{imageNames["cni"]}
      tag: #{components["calico/cni"]["version"]}
    kubeControllers:
      image: #{imageRegistry}#{imageNames["kubeControllers"]}
      tag: #{components["calico/kube-controllers"]["version"]}
    flannel:
      image: #{imageNames["flannel"]}
      tag: #{components["flannel"]["version"]}
    dikastes:
      image: #{imageRegistry}#{imageNames["dikastes"]}
      tag: #{components["calico/dikastes"]["version"]}
    flexvol:
      image: #{imageRegistry}#{imageNames["flexvol"]}
      tag: #{components["flexvol"]["version"]}
    EOF
end
