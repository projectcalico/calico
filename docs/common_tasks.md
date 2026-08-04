### Adding a new CRD

New APIs are added using the `operator-sdk` tool.

```
operator-sdk create api --group=operator.tigera.io --version=v1 --kind=<Kind> --resource --namespaced=false
```

When modifying or adding CRDs, you will need to run `make gen-files` to update the auto-generated files. The tool
might change the scope of existing resources to "Namespaced", so make sure to set them back to their desired state.

See this demo pull request for more detail on adding both a controller and CRD: https://github.com/tigera/operator/pull/3587

### Adding a new controller

New controllers are also added using the `operator-sdk` tool.

```
operator-sdk create api --group=operator.tigera.io --version=v1 --kind=<Kind> --controller
```

New controllers will be created in the newer format so it should be considered if it is desirable to keep the
current format that calls to a controller in `pkg/controller` or add the controller only in `controllers`.

### Running it locally

You can create a local k3d cluster with the Makefile:

	make cluster-create

Export the kubeconfig:

	export KUBECONFIG=./kubeconfig.yaml

Create the tigera-operator namespace:

	kubectl create ns tigera-operator

Then, run the operator against the local cluster:

	# enable-leader-election is necessary since you'll be running the operator outside of a cluster
	KUBECONFIG=./kubeconfig.yaml go run ./ --enable-leader-election=false

To launch Calico, install the default custom resource:

	kubectl create -f ./config/samples/operator_v1_installation.yaml

To tear down the cluster:

	make cluster-destroy

#### Running a custom image in your existing Calico (Enterprise) cluster

These steps assume that you already have installed the operator in a Calico (Enterprise) cluster after following either
docs.projectcalico.org or docs.tigera.io. To verify, run `kubectl get deployment -n tigera-operator tigera-operator`.
You should see an existing deployment.
The steps also assume that you have setup your docker such that you can push to a registry.

These are the steps:
1. Make your own code changes to this repository.
2. Create the binaries and a docker image.
   ```bash
   make image
   ```
   The output will show you the docker tag that was just created. (For example: `Successfully tagged tigera/operator:latest-amd64`.)
3. Re-tag the image and push it to a registry of your choice.
   ```
   export IMAGE=myregistry.com/user/tigera/operator:my-tag
   docker tag tigera/operator:latest $IMAGE
   docker push $IMAGE
   ```
4. Change your deployment to use the image.
   ```
   kubectl set image deploy  -n tigera-operator tigera-operator  tigera-operator=$IMAGE
   ```
   _If your image is in a private registry, you also need to add [imagePullSecrets](https://kubernetes.io/docs/concepts/containers/images/) to the deployment._

#### Set breakpoints in Goland IDE and run the code against your existing Calico (Enterprise) cluster

These steps assume that you already have installed the operator in a Calico (Enterprise) cluster after following either
https://docs.projectcalico.org or https://docs.tigera.io. To verify, run `kubectl get deployment -n tigera-operator tigera-operator`.
You should see an existing deployment. Install [kubefwd](https://kubefwd.com/).

1. Scale down the operator, so it does not interfere with your own:
```bash
kubectl scale deploy -n tigera-operator tigera-operator --replicas=0
```
2. Run kubefwd in a separate terminal, so pods and service names are accessible from your local computer.
```bash
kubefwd svc -n calico-system -n tigera-kibana -n tigera-manager -n tigera-dex -n tigera-elasticsearch -n tigera-prometheus -c $KUBECONFIG
```
3. Open a code file in your editor and set a breakpoint.
4. Create a debug configuration by right-clicking main.go and select `modify run configuration`.
   1. Under Run kind, select `Package`
   2. Under Environment, add `KUBECONFIG=/path/to/config`
   3. In Program arguments, add `--enable-leader-election=false`
5. Save the configuration. You can now run it in debug mode.

### Using Calico Enterprise

To install Calico Enterprise instead of Calico, you need to install an image pull secret,
as well as modify the Installation CR.

Create the pull secret in the tigera-operator namespace:

```
kubectl create secret -n tigera-operator generic tigera-pull-secret \
    --from-file=.dockerconfigjson=<PATH/TO/PULL/SECRET> \
    --type=kubernetes.io/dockerconfigjson
```

Then, modify the installation CR (e.g., with `kubectl edit installations`) to include the following:

```
spec:
  variant: CalicoEnterprise
  imagePullSecrets:
  - name: tigera-pull-secret
```

You can then install additional Calico Enterprise components by creating their CRs from within
the `./deploy/crds/` directory.

### Running unit tests

To run all the unit tests, run:

	make test

To run a specific test or set of tests, use the `GINKGO_FOCUS` argument.

	make test GINKGO_FOCUS="component function tests"

### Making temporary changes to components the operator manages

The operator creates and manages resources and will reconcile them to be in the desired state. Due to the
reconciliation it does, if a user makes direct changes to a resource the operator will revert those changes.
To enable the user to make temporary changes, an annotation can be added to any resource directly managed by
the operator which will cause the operator to no longer update the resource.
Adding the following as an annotation to any resource will prevent the operator from making any future updates to the annotated resource:

  *Do not use this unless you are a developer working on the operator. If you add this annotation,
  you must remove it before the operator can manage the resource again.*

  ```
  unsupported.operator.tigera.io/ignore: "true"
  ```

#### Example update to calico-node DaemonSet

Notice that the annotation is added in the top level metadata (not in the spec.template.metadata).
(note the below is not a valid manifest but just an example)
```
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-node
  namespace: calico-system
  labels:
    k8s-app: calico-node
  annotations:
    # You should NOT use this unless you want to block the operator from doing its job managing this resource.
    unsupported.operator.tigera.io/ignore: "true"
spec:
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      containers:
        - name: calico-node
          image: calico/node:my-special-tag
```

### Updating the bundled version of Envoy Gateway

1. In `go.mod`, update the version for `github.com/envoyproxy/gateway`.

1. Run `make mod-tidy`.  If this indicates needing other changes, e.g. bumping the go-build version, do that.  (For example, for a possible move to Envoy Gateway v1.3.2 - not yet committed - I needed to update `GO_BUILD_VER` from `v0.95` to `1.23.6-llvm18.1.8-k8s1.31.5`, because Envoy Gateway v1.3.2 requires golang v1.23.6.)

1. In `Makefile`, update `ENVOY_GATEWAY_VERSION`.

1. Delete `pkg/render/gatewayapi/gateway-helm.tgz`.

1. Run `make build`.  This will download the new version of the Envoy Gateway helm chart and build the operator image.  The chart is embedded in the binary and rendered at runtime using the Helm SDK.

1. Address build issues if there are any.

1. Run `make ut`, and address issues if there are any.

1. Commit everything and post as a `tigera/operator` PR.

1. Identify the corresponding new versions of the `gateway`, `proxy` and `ratelimit` images.

   - The `gateway` version can be found in the Envoy Gateway release notes ([for example](https://github.com/envoyproxy/gateway/releases/tag/v1.3.2)).  It should be the same as the nominal Envoy Gateway version that you're updating to.

   - The `proxy` version can be found in the Envoy Gateway release notes, or by referring to [this compatibility matrix](https://gateway.envoyproxy.io/news/releases/matrix/).

   - The `ratelimit` version can be found in the Envoy Gateway release notes.

1. Switching to the `projectcalico/calico` repo, update the code under `third_party/envoy-{gateway,proxy,ratelimit}` to build those new image versions.  In each case:

   - Update the relevant version (e.g. `ENVOY_GATEWAY_VERSION`) in `Makefile`.

   - Review if any existing patches are still required, and remove them if not.

   - Review if any existing patches still apply cleanly, and update them if not.

1. Commit everything and post as a `projectcalico/calico` PR.

1. Review, address issues, merge, monitor hashrelease builds, address any further issues, etc.
