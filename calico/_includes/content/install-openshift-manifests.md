Download the {{site.prodname}} manifests for OpenShift and add them to the generated manifests directory:

```bash
wget -qO- {{ "/manifests/ocp.tgz" | absolute_url }} | tar xvz -C calico
cp calico/* manifests/
```
