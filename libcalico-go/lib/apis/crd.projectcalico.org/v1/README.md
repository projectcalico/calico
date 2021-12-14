# CustomResourceDefinitions

This directory is used for generating CustomResourceDefinition resources to install into a Kubernetes
cluster. Calico APIs that are backed using CRDs should be added here so that auto-generation picks up
the API. See other structs in this directory as an example.

Once added, run `make gen-crds` in the root of this repository to update the custom resource definition yamls.

Then, once merged, use those yamls to update the CRDs served from https://github.com/projectcalico/calico
