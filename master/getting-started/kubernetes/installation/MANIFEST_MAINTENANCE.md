## Managing manifests

This doc is around how we handle the many manifests that are kept here and
below for the purpopses of deploying Calico.  There are many factors that
cause us to create new manifests or modify existing manifests and this document
tries to ensure we are consistent with our handling of them (until the scheme
is changed).

* A new manifest should be added when there is a breaking change to a current
  manifest.
* Manifests should at most be kept for 3 revisions of kubernetes.
* Manifests should be placed in a folder indicating the version of kubernetes
  for which they were created.
  * As new versions of kubernetes are released the folder name should not be
    updated though the docs should be updated to indicate the versions.
    (ex. When new manifests were created for K8s 1.7 with CRDs a new 1.7
    folder was created but no new manifest is created for K8s 1.8 as the same
    versions work on both 1.7 and 1.8.)
* We should strive to keep the number of different configurations the few we
  need.
  Currently we have: "standard" (etcd), kubeadm (etcd), KDD with networking,
  KDD with user supplied networking.
