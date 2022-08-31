Download the {{site.prodname}} manifests for OpenShift and add them to the generated manifests directory:

```bash
mkdir calico
wget -qO- {{ "/manifests/ocp.tgz" | absolute_url }} | tar xvz --strip-components=1 -C calico
cp calico/* manifests/
```
