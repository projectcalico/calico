---
title: Install images by registry digest
description: Specify the digests for operator to use to deploy images.
canonical_url: '/maintenance/image-options/imageset'
---

{% assign operator = site.data.versions.first.tigera-operator %}

### Big picture

Deploy images by container registry digest for operator installations.

### Value

Some deployments have strict security requirements that require deploying images by immutable digest instead of tags.
Once released, official {{site.prodname}} images and tags will not be modified. However using an immutable digest allows specific images to be reviewed
and verified by security teams.

### Features

This how-to guide uses the following {{site.prodname}} features:

* **ImageSet**

### Concepts

#### Container registry

A container registry provides access to container images referenced by tags or digest.

#### Image tag

Versioned container images are typically referenced by a tag which is appended to an image reference. Example: `<repo>/<image>:<tag>`. Container image tags are typically not expected be changed or updated, but this is not required or enforced by most image registries, meaning it is possible to push new code to the same image tag.

#### Image digest

Container images, when added to a container registry, have a unique hash created that can be used to pull a specific version of an image that cannot be changed or updated.

### Before you begin

**Required**
- {{site.prodname}} managed by the operator
- Docker client is configured to pull images from the container registries where images are stored
- Kubernetes permissions to apply an ImageSet manifest to your cluster

### How to

1. [Update the operator deployment with a digest](#update-the-operator-deployment-with-a-digest)
2. [Create an ImageSet](#create-an-imageset)
3. [Verify the correct ImageSet is being used](#verify-the-correct-imageset-is-being-used)

**Other tasks**

- [Create new ImageSet when upgrading or downgrading](#create-new-imageset-when-upgrading-or-downgrading)

**Troubleshooting**

- [Why does the Installation resource status not include my ImageSet?](#why-does-the-installation-resource-status-not-include-my-imageset)
- [How can I tell if there is a problem with my ImageSet?](#how-can-i-tell-if-there-is-a-problem-with-my-imageset)

#### Update the operator deployment with a digest

Before applying `tigera-operator.yaml`, modify the operator deployment to use the operator image digest.

Use commands like the following to get the image digest (adjust the image in the commands if you are using a different operator image):
```bash
docker pull {{ operator.registry }}/{{ operator.image }}:{{ operator.version }}
docker inspect {{ operator.registry }}/{{ operator.image }}:{{ operator.version }} -f {% raw %}'{{range .RepoDigests}}{{printf "%s\n" .}}{{end}}'{% endraw %}
```

If multiple digests are returned, select the one matching the registry you are using.

Update the tigera-operator deployment:
```bash
sed -ie "s|\(image: .*/operator\):.*|?\1@<put-digest-here>|" tigera-operator.yaml
```

#### Create an ImageSet

Create an [ImageSet]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.ImageSet) manifest file named `imageset.yaml` like the following:

```yaml
apiVersion: operator.tigera.io/v1
kind: ImageSet
metadata:
  name: calico-{{site.data.versions.first.title}}
spec:
  images:
  - image: "calico/apiserver"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "calico/cni"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "calico/kube-controllers"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "calico/node"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "calico/typha"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "calico/pod2daemon-flexvol"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "calico/windows-upgrade"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "tigera/operator"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  - image: "tigera/key-cert-provisioner"
    digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

You can create an ImageSet manifest manually or by script.

{% tabs tab-group:grp1 %}
<label:Manual,active:true>
<%

1. Copy the above example into a file called `imageset.yaml` and edit that file in the steps below.
1. Set the name for your ImageSet to `calico-<version>` (Example: `calico-{{site.data.versions.first.title}}`).
   The version can be obtained by running:
   ```
   docker run {{ operator.registry }}/{{ operator.image }}:{{ operator.version }} --version
   ```
1. Add the correct digest for each image. If you are using a private registry, ensure you pull the image from the private registry and use the digest associated with the private registry.
     1. If using the default images, get a list of them by running:
        ```
        docker run {{ operator.registry }}/{{ operator.image }}:{{ operator.version }} --print-images=list
        ```
        >**Note**: If you are not using the default image registries or paths, you must create your own list of images (and the above command will not apply).
        {: .alert .alert-info}
        >**Note**: The list will contain images for an Enterprise deployment but they do not need to be added to the ImageSet.
        {: .alert .alert-info}
     1. Get the needed digests by using the images returned from the above step in the following command:
        ```
        docker pull <repo/image:tag> && docker inspect <repo/image:tag> -f {% raw %}'{{range .RepoDigests}}{{printf "%s\n" .}}{{end}}'{% endraw %}
        ```
     1. Use the digest from the image that matches the repo/image you will use.
        If you are using a private registry or have specified an [imagePath]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.Installation)
        you will still use the "default" `<owner>/<image>` in the `image` field, for example if you your node image is coming from
        `example.com/registry/imagepath/node` you will still use `calico/node` in the image field of the ImageSet.
        >**Example**: For image `quay.io/tigera/operator@sha256:d111db2f94546415a30eff868cb946d47e183faa804bd2e9a758fd9a8a4eaff1` copy everything after `@` and add it as the digest for the `tigera/operator` image.
        {: .alert .alert-info}

%>
<label:Script>
<%

Copy the following script into a file, make it executable, and run the script. The script creates an `imageset.yaml` file in the directory it was run.
>**Note**: This script will only work if using the default registries and image paths.
{: .alert .alert-info}

```
#!/bin/bash -e

images=(calico/apiserver calico/cni calico/kube-controllers calico/node calico/typha calico/pod2daemon-flexvol calico/windows-upgrade tigera/key-cert-provisioner tigera/operator)

OPERATOR_IMAGE={{ operator.registry }}/{{ operator.image }}:{{ operator.version }}
echo "Pulling $OPERATOR_IMAGE"
echo
docker pull $OPERATOR_IMAGE -q >/dev/null
versions=$(docker run $OPERATOR_IMAGE --version)
ver=$(echo -e "$versions" | grep 'Calico:')

imagelist=($(docker run $OPERATOR_IMAGE --print-images=list))

cat > ./imageset.yaml <<EOF
apiVersion: operator.tigera.io/v1
kind: ImageSet
metadata:
  name: calico-$(echo $ver | sed -e 's|^.*: *||')
spec:
  images:
EOF

for x in "${imagelist[@]}"; do
  for y in ${images[*]}; do
    if [[ $x =~ $y: ]]; then
      digest=$(docker run --rm gcr.io/go-containerregistry/crane:v0.7.0 digest ${x})
      echo "Adding digest for $x"
      echo 
      echo "  - image: \"$(echo $x | sed -e 's|^.*/\([^/]*/[^/]*\):.*$|\1|')\"" >> ./imageset.yaml
      echo "    digest: \"$digest\"" >> ./imageset.yaml
    fi
  done
done
```
%>
{% endtabs %}

Apply the created `imageset.yaml` to your cluster.

#### Verify the correct ImageSet is being used

1. Check tigerastatus for components that are Degraded with `kubectl get tigerastatus`.
   - If any components show Degraded, [investigate further](#how-can-i-tell-if-there-is-a-problem-with-my-imageset).
2. When tigerastatus for all components show Available True, the ImageSet has been applied.
   ```
   NAME     AVAILABLE   PROGRESSING   DEGRADED   SINCE
   calico   True        False         False      54s
   ```
3. Verify that the correct ImageSet is being used. In Installation status, check that the `imageset` field is set to the ImageSet you created.
   Check the field by running the following command:
   ```
   kubectl get installation default -o yaml | grep imageSet
   ```
   You should see output similar to:
   ```
       imageSet: calico-{{site.data.versions.first.title}}
   ```

### Other tasks

#### Create new ImageSet when upgrading or downgrading

Before upgrading to a new release or downgrading, you must create a new [ImageSet]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.ImageSet)
with updated image references and names for the new release. This must be done prior
to upgrading the cluster so when the new manifests are applied, the appropriate ImageSet is available.

### Troubleshooting

#### Why does the Installation Resource status not include my ImageSet?

The [status.imageset]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.InstallationStatus) field of
the Installation Resource will not be updated until the `calico` component has fully been deployed. `calico` is
fully deployed when `kubectl get tigerastatus calico` reports Available True with Progressing and Degraded as False.

#### How can I tell if there is a problem with my ImageSet?

If you suspect an issue with your ImageSet, check tigerastatus with `kubectl get tigerastatus`. If any components are
degraded, you can get additional information with `kubectl get tigerastatus <component-name> -o yaml`. If the digest
provided for an image is incorrect or unable to be pulled, the tigerastatus will not directly report that information,
but you should see information that there is an issue rolling out a Deployment, Daemonset, or Job. If you suspect
an issue with a resource rollout due to an issue with an image, you will need to `get` or `describe` a specific pod
to see details about the problem.

