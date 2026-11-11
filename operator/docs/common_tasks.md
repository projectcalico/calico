# Common Tasks

Day-to-day development procedures for the operator. All `make` targets below run
from `operator/`. For the architecture and its invariants, see
[../DESIGN.md](../DESIGN.md); for code-generation rules, see
[api_design.md](api_design.md).

## Adding a new CRD

New APIs are added using the `operator-sdk` tool.

```
operator-sdk create api --group=operator.tigera.io --version=v1 --kind=<Kind> --resource --namespaced=false
```

When modifying or adding CRDs, you will need to run `make gen-files` to update the auto-generated files. The tool
might change the scope of existing resources to "Namespaced", so make sure to set them back to their desired state.

See this demo pull request for more detail on adding both a controller and CRD: https://github.com/tigera/operator/pull/3587

## Adding a new controller

New controllers are also added using the `operator-sdk` tool.

```
operator-sdk create api --group=operator.tigera.io --version=v1 --kind=<Kind> --controller
```

New controllers will be created in the newer format so it should be considered if it is desirable to keep the
current format that calls to a controller in `pkg/controller` or add the controller only in `controllers`.

## Running it locally

Create a local kind cluster with the Makefile:

	make kind-cluster-create

Export the kubeconfig it writes:

	export KUBECONFIG=../hack/test/kind/kind-kubeconfig.yaml

Create the tigera-operator namespace:

	kubectl create ns tigera-operator

Then, run the operator against the local cluster:

	# enable-leader-election is necessary since you'll be running the operator outside of a cluster
	go run ./cmd/main.go --enable-leader-election=false

To launch Calico, install the default custom resource:

	kubectl create -f ./config/samples/operator_v1_installation.yaml

To tear down the cluster:

	make kind-cluster-destroy

### Running a custom image in your existing Calico (Enterprise) cluster

These steps assume that you already have installed the operator in a Calico (Enterprise) cluster after following
docs.tigera.io. To verify, run `kubectl get deployment -n tigera-operator tigera-operator`.
You should see an existing deployment.
The steps also assume that you have setup your docker such that you can push to a registry.

These are the steps:
1. Make your own code changes to the operator.
2. Create the binaries and a docker image.
   ```bash
   make image
   ```
   The output will show you the docker tag that was just created. (For example: `Successfully tagged operator:latest-amd64`.)
3. Re-tag the image and push it to a registry of your choice.
   ```
   export IMAGE=myregistry.com/user/operator:my-tag
   docker tag operator:latest $IMAGE
   docker push $IMAGE
   ```
4. Change your deployment to use the image.
   ```
   kubectl set image deploy  -n tigera-operator tigera-operator  tigera-operator=$IMAGE
   ```
   _If your image is in a private registry, you also need to add [imagePullSecrets](https://kubernetes.io/docs/concepts/containers/images/) to the deployment._

### Set breakpoints in Goland IDE and run the code against your existing Calico (Enterprise) cluster

These steps assume that you already have installed the operator in a Calico (Enterprise) cluster after following
https://docs.tigera.io. To verify, run `kubectl get deployment -n tigera-operator tigera-operator`.
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
4. Create a debug configuration by right-clicking `cmd/main.go` and select `modify run configuration`.
   1. Under Run kind, select `Package`
   2. Under Environment, add `KUBECONFIG=/path/to/config`
   3. In Program arguments, add `--enable-leader-election=false`
5. Save the configuration. You can now run it in debug mode.

## Using Calico Enterprise

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

## Running unit tests

To run the unit tests, run:

	make ut

`UT_DIR` defaults to `./pkg`; pass `UT_DIR=.` to cover every package in the operator. To run a
specific test or set of tests, narrow `UT_DIR` to the Ginkgo suites you want and focus within them.
Packages that do not use Ginkgo reject the focus flag, so `UT_DIR` is required here.

	make ut UT_DIR=./pkg/render GINKGO_FOCUS="component function tests"

## Making temporary changes to components the operator manages

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

### Example update to calico-node DaemonSet

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

## Updating the bundled version of Envoy Gateway

1. In the repo root `go.mod`, update `github.com/envoyproxy/gateway`, and `sigs.k8s.io/gateway-api` (plus `/conformance`) to the version that Envoy Gateway release requires. Run `make mod-tidy`. If the new version needs a newer Go than `GO_BUILD_VER` in `metadata.mk` provides, that has to move first.

1. In `operator/Makefile`, update `ENVOY_GATEWAY_VERSION`.

1. Delete `operator/pkg/render/gatewayapi/gateway-helm.tgz`. It is gitignored and only downloaded when absent, so a stale chart is otherwise reused silently.

1. Run `make -C operator build` and `make -C operator ut`, and address any issues. The chart is embedded in the binary and rendered at runtime using the Helm SDK.

1. Identify the matching `proxy` and `ratelimit` images. Read them from `charts/gateway-helm/values.tmpl.yaml` in the envoyproxy/gateway repo at the exact tag you are moving to; the [compatibility matrix](https://gateway.envoyproxy.io/news/releases/matrix/) can lag behind patch releases.

1. Update `third_party/` at the repo root to build those images:

   - `third_party/envoy-gateway/Makefile`: `ENVOY_GATEWAY_VERSION`.

   - `third_party/envoy-ratelimit/Makefile`: `ENVOY_RATELIMIT_VERSION`, as a full commit SHA.

   - `third_party/envoy-proxy/Makefile`: `ENVOYBINARY_IMAGE`. This is built from tigera/envoybinary, so a new Envoy version must be merged and published there first.

   - Review each component's `patches/01-custom-patches/` and drop any patch that landed upstream. Do not hand-edit `patches/02-auto-gen-patches/`; run `make -C third_party/<component> regen-dep-patches` and commit whatever it produces.

1. If the Gateway API bundle adds CRDs, add them to the operator's RBAC in `charts/tigera-operator/templates/tigera-operator/02-role-tigera-operator.yaml` and run `make gen-manifests`. Check `envoyGatewayCuratedSet` in `e2e/cmd/gateway/e2e_test.go` against the new tag's `test/conformance/suite.go`.

1. Run `make gen-deps-files`.

1. Commit everything and post as a single PR.

1. Review, address issues, merge, monitor hashrelease builds, address any further issues, etc.

## Updating the bundled version of Istio

Istio is pinned in two places that move together. `ISTIO_VERSION` in `istio/Makefile` builds the istiod, ztunnel, istio-cni and proxyv2 images from the upstream istio and ztunnel source tags; Renovate tracks that pin as `istio/istio` (see `renovate.json`). `ISTIO_VERSION` and `ISTIO_HELM_REPO` in `operator/Makefile` fetch the `base`, `istiod`, `cni` and `ztunnel` Helm charts the operator renders; nothing tracks that pin, so move it by hand. With the two on different tags, one version's charts render the Deployment, DaemonSets and environment around another version's binaries.

1. In `istio/Makefile`, update `ISTIO_VERSION`.

1. Rebase the hand-written patches in `istio/patches/01-custom-patches/` and `istio/ztunnel-patches/01-custom-patches/` onto the new source tags. `make -C istio init-sources` downloads both trees into `istio/istio` and `istio/ztunnel` and applies the patches with `-F0`, so a hunk whose context no longer matches fails instead of landing somewhere approximate (offsets are fine); `make -C istio clean` removes the trees and the stamps so it can be re-run. Regenerate a patch whose hunks only moved so it applies cleanly, and explain any content change in the commit body. A patch that carries an open upstream fix says so in its header; drop it once the new tag ships the fix. Prove the result compiles without building the images: `go build ./cni/...` and `go test ./pilot/pkg/credentials/kube/` in `istio/istio`, `cargo check` in `istio/ztunnel`.

1. Regenerate `istio/patches/02-auto-gen-patches/` with `make -C istio regen-dep-patches`: the dependency patch is derived from `istio/dep-pins.txt` against the new tag's `go.mod`, and a pin the new tag already satisfies drops out of it. `make -C istio check-dep-patches` confirms the checked-in patch matches. Do not edit the generated patch by hand.

1. In `operator/Makefile`, update `ISTIO_VERSION`, and `ISTIO_HELM_REPO` if the chart host moved. From 1.31 the charts are published at `https://blob.istio.io/istio-release/charts`; the old `istio-release.storage.googleapis.com` host carries no 1.31 charts.

1. Delete `operator/pkg/render/istio/*.tgz`. They are gitignored and only downloaded when absent, so stale charts are otherwise reused silently. `make -C operator istio_charts` fetches the new ones.

1. Check that every chart value the operator sets in `operator/pkg/render/istio/config.go` still exists in the new charts' `values.yaml` and templates and still means the same thing. `istio.go` also relies on two chart-side conventions: the `cni` chart copies `cni.*` to the top level (`templates/zzy_descope_legacy.yaml`), and the charts resolve `global.platform` to the platform profile (`templates/zzz_profile.yaml`).

1. Run `make -C operator ut UT_DIR=./pkg/render/istio` and `make -C operator ut UT_DIR=./pkg/controller/istio`, and address any issues. `pkg/render/istio/istio_test.go` asserts the CRD list from the `base` chart and the object counts from all four charts, so a release that adds a CRD or a resource changes those expectations.

1. Read the upstream upgrade notes for every minor release crossed (`https://istio.io/latest/news/releases/<minor>.x/announcing-<minor>/upgrade-notes/`) and record anything that changes behaviour for an operator-managed ambient install. The Gateway API CRD requirement is the usual one: the operator creates those CRDs from the Envoy Gateway chart and only when they are absent, so check the bundle version there against what the new Istio requires. Copy the new tag's `MinimumCRDVersions` from `pkg/config/schema/gatewayapi/minimumversions.go` into `istioGatewayAPIMinimumVersions` in `operator/pkg/controller/istio/gatewayapi_crds.go`; the operator warns on the `istio` TigeraStatus about existing CRDs below those versions.

1. Commit everything and post as a single PR.
