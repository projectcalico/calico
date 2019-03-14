def gen_values(versions, imageNames, version, prodname, nodecontainer, imageRegistry)
    components = versions[version][0]["components"]
    versionsYml = <<~EOF
    node:
      image: #{imageNames["node"]}
      tag: #{components["calico/node"]["version"]}
    calicoctl:
      image: #{imageNames["calicoctl"]}
      tag: #{components["calicoctl"]["version"]}
    typha:
      image: #{imageNames["typha"]}
      tag: #{components["typha"]["version"]}
    cni:
      image: #{imageNames["cni"]}
      tag: #{components["calico/cni"]["version"]}
    kubeControllers:
      image: #{imageNames["kubeControllers"]}
      tag: #{components["calico/kube-controllers"]["version"]}
    flannel:
      image: #{imageNames["flannel"]}
      tag: #{components["flannel"]["version"]}
    dikastes:
      image: #{imageNames["dikastes"]}
      tag: #{components["calico/dikastes"]["version"]}
    flexvol:
      image: #{imageNames["flexvol"]}
      tag: #{components["flexvol"]["version"]}
    prodname: #{prodname}
    nodecontainer: #{nodecontainer}
    imageRegistry: #{imageRegistry}
    EOF
end
