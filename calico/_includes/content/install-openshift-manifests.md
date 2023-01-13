Download the {{site.prodname}} manifests for OpenShift and add them to the generated manifests directory:

```bash
mkdir calico
wget -qO- https://github.com/projectcalico/calico/releases/download/{{page.version}}/ocp.tgz | tar xvz --strip-components=1 -C calico
cp calico/* manifests/
```
