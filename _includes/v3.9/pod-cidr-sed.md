1. If you are using pod CIDR {% if include.yaml == "calico" %}`192.168.0.0/16`{% else %}`10.244.0.0/16`{% endif %}, skip to the next step. If you
   are using a different pod CIDR, use the following commands to set an environment
   variable called `POD_CIDR` containing your pod CIDR and
   replace {% if include.yaml == "calico" %}`192.168.0.0/16`{% else %}`10.244.0.0/16`{% endif %} in the manifest with your pod CIDR.

   ```bash
   POD_CIDR="<your-pod-cidr>" \
   sed -i -e "s?{% if include.yaml == "calico" %}192.168.0.0/16{% else %}10.244.0.0/16{% endif %}?$POD_CIDR?g" {{include.yaml}}.yaml
   ```
