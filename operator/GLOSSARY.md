# Operator glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `operator/`. The operator's design rules are in [DESIGN.md](DESIGN.md).

## Building blocks

The top layer of the operator process.

| Building block | Code | Responsible for |
|---|---|---|
| Daemon | `operator/pkg/daemon/daemon.go` (`Run`) | Resolves the variant, builds the extensions, starts the controller-runtime manager and adds the controllers. |
| Controller registry | `operator/internal/controller/controllers.go` (`AddToManager`) | Registers each kubebuilder reconciler shell, which calls the matching `Add` in `operator/pkg/controller/<name>`. |
| Controllers | `operator/pkg/controller/` | One controller per feature or per status area. See the second table. |
| Component handler | `operator/pkg/controller/utils/component.go` (`ComponentHandler`) | Applies one component render implementation's objects to the cluster. |
| Status manager | `operator/pkg/controller/status/status.go` (`StatusManager`) | Watches registered workloads and CSRs and writes one TigeraStatus. |
| Certificate manager | `operator/pkg/controller/certificatemanager/certificatemanager.go` (`CertificateManager`) | The operator CA: signs key pairs, preserves BYO certificates and builds trusted bundles. |
| Field manager | `operator/pkg/controller/managedfields/fieldmanager.go` (`FieldManager`) | Writes declared fields on FelixConfiguration and BGPConfiguration through server-side apply. |
| Render package | `operator/pkg/render/component.go` (`Component`) | Pure generators of the objects to create and delete for each feature. |
| Extensions | `operator/pkg/extensions/extensions.go` (`Set`) | One hook interface per controller that another product variant implements. |
| Image components | `operator/pkg/components/references.go` (`Component`) | Image name, version, registry and variant for each deployable image. |
| API types | `operator/api/v1/` | The `operator.tigera.io/v1` input and status types. |

The controllers, one layer down.

| Controller | Code | Responsible for |
|---|---|---|
| Installation controller | `operator/pkg/controller/installation/core_controller.go` (`ReconcileInstallation`) | Renders calico-node, Typha, kube-controllers, the CSI driver, namespaces and CRDs. Owns the `calico` TigeraStatus. |
| Windows controller | `operator/pkg/controller/installation/windows_controller.go` | Renders calico-node-windows. Owns the `calico-windows` TigeraStatus. |
| APIServer controller | `operator/pkg/controller/apiserver/apiserver_controller.go` | Renders the Calico apiserver and holds the APIService cutover. |
| IP pool controller | `operator/pkg/controller/ippool/pool_controller.go` | Turns the Installation's IP pools into `projectcalico.org/v3` IPPools. Owns the `ippools` TigeraStatus. |
| CSR controller | `operator/pkg/controller/csr/csr_controller.go` | Approves and signs CSRs for the signer `tigera.io/operator-signer`. |
| Cluster CA controller | `operator/pkg/controller/secrets/cluster_ca_controller.go` | Keeps the operator CA secret in place. |
| Whisker, Goldmane, Gateway API, Istio and Tiers controllers | `operator/pkg/controller/whisker/`, `operator/pkg/controller/goldmane/`, `operator/pkg/controller/gatewayapi/`, `operator/pkg/controller/istio/`, `operator/pkg/controller/tiers/` | One feature each. |
| Kube-proxy monitor and pod IP recovery | `operator/pkg/controller/kubeproxy/`, `operator/pkg/controller/podiprecovery/` | Auxiliary controllers: they have no CRD of their own. |

## Terms

### Rendering and applying

**Component render implementation**:
A value implementing the `render.Component` interface. It returns the objects to create and delete for one feature, and it makes no API calls. Code today calls it a "render component", and a follow-on refactor will rename the type.
Code: `operator/pkg/render/component.go` (`Component`).
_Avoid_: component, unqualified; renderer

**Component handler**:
The applier that takes one component render implementation and creates, updates or deletes its objects against the cluster, merging with current state and registering its workloads with a status manager.
Code: `operator/pkg/controller/utils/component.go` (`ComponentHandler`).
_Avoid_: renderer (the handler applies, it does not render)

**CreateOrUpdateOrDelete**:
The component handler entry point that applies a component render implementation and registers its workloads with the status manager.
Code: `operator/pkg/controller/utils/component.go` (`CreateOrUpdateOrDelete`).
_Avoid_: reconcile (that is the controller's job)

**`SetCreateOnly`**:
A component handler mode that creates missing objects and never corrects existing ones.
Code: `operator/pkg/controller/utils/component.go` (`SetCreateOnly`).

**Render precondition**:
The `Ready()` check on a component render implementation. When it returns false, the handler skips that component for this reconcile.
Code: `operator/pkg/render/component.go` (`Ready`).
_Avoid_: ready (TigeraStatus has its own Ready)

**Apply-time decoration**:
The per-object fix-ups the component handler makes as it applies objects: standard labels, OS node selectors, TLS environment variables and the API group variable. It is separate from the extensions' `Decorate`.
Code: `operator/pkg/controller/utils/component.go` (`ComponentHandler`).
_Avoid_: handler normalization

**Passthrough**:
A component render implementation that returns a fixed object list unchanged.
Code: `operator/pkg/render/passthru.go` (`NewCreationPassthrough`).

**Overridable**:
A component render implementation whose workloads take user overrides after any modifier from a variant.
Code: `operator/pkg/render/component.go` (`Overridable`).

**Override target**:
One object (kind, namespace and name) plus the override struct applied to it.
Code: `operator/pkg/render/common/components/override_targets.go`.

**Overrides**:
User-supplied Deployment and DaemonSet fields, such as `CalicoNodeDaemonSet` and `TyphaDeployment`, applied onto rendered workloads.
Code: `operator/api/v1/installation_types.go` (`InstallationSpec`).
_Avoid_: override, unqualified

**Ignore annotation**:
The annotation `unsupported.operator.tigera.io/ignore`. It stops the handler managing an object and raises a status warning.
Code: `operator/pkg/controller/utils/utils.go`.

### Variants and extensions

**Variant**:
The product the operator runs as, fixed for the life of the process. A change of variant restarts the operator.
Code: `operator/api/v1/installation_types.go` (`ProductVariant`).
_Avoid_: flavor, edition

**Extension**:
A variant's per-controller hook set. Core code never branches on the variant; it calls the extension.
Code: `operator/pkg/extensions/extensions.go` (`Set`).
_Avoid_: plugin

**Controller phase**:
The extension phase with cluster access, run through `ExtendInputs`. It does the side-effecting work a render hook cannot, such as rejecting unsupported config or creating certificates.
Code: `operator/pkg/extensions/doc.go`.

**Render phase**:
The extension phase made of pure hooks (`Modify`) that adjust a component render implementation's objects.
Code: `operator/pkg/extensions/component.go` (`Modifier`).

**Modifier**:
A function that post-processes a component render implementation's objects for a variant. `Decorate` wraps a component so its modifier runs before user overrides.
Code: `operator/pkg/extensions/component.go` (`Decorate`).

**`WithDerive`**:
A modifier that runs after overrides and builds objects copied from overridden ones.
Code: `operator/pkg/extensions/component.go` (`WithDerive`).

### Status

**Status area**:
The unit that one TigeraStatus reports on, such as `calico`, `apiserver` or `ippools`. Each status area has one controller and one status manager. The API calls it a functional area.
Code: `operator/api/v1/tigerastatus_types.go` (`TigeraStatus`).
_Avoid_: component

**TigeraStatus**:
The cluster-scoped resource that reports one status area's conditions, named per controller.
Code: `operator/api/v1/tigerastatus_types.go` (`TigeraStatus`).

**Status manager**:
The per-controller object that tracks registered workloads and conditions and writes one TigeraStatus.
Code: `operator/pkg/controller/status/status.go` (`StatusManager`).
_Avoid_: manager, unqualified

**Degraded, Progressing and Available**:
The three independent TigeraStatus condition types. `Ready` on the resource's status repeats Available.
Code: `operator/api/v1/tigerastatus_types.go` (`TigeraStatusDegraded`).

**Status warning**:
A keyed message appended to the TigeraStatus `message` that does not mark the status area degraded.
Code: `operator/pkg/controller/status/status.go`.

**Auxiliary controller**:
A controller with no CRD of its own: the kube-proxy monitor, pod IP recovery and, as a status-only case, the IP pool controller.
Code: `operator/pkg/controller/kubeproxy/controller.go`.
_Avoid_: CR-less controller

### Certificates and trust

**Operator CA**:
The CA secret the operator holds, plus the trusted bundle built from it. The certificate manager issues, loads and preserves key pairs against it.
Code: `operator/pkg/controller/certificatemanager/certificatemanager.go` (`CertificateManager`).
_Avoid_: certificate management (that is a different feature), signer

**Key pair**:
A Secret holding a private key and certificate, signed by the operator CA, supplied by the user (BYO), or backed by a CSR.
Code: `operator/pkg/tls/certificatemanagement/interface.go` (`KeyPairInterface`).
_Avoid_: cert, unqualified

**BYO certificate**:
A key pair the user supplied. The operator preserves it and never re-signs it.
Code: `operator/pkg/tls/certificatemanagement/keypair.go`.
_Avoid_: user-provided certificate

**Trusted bundle**:
A ConfigMap of CA certificates mounted into pods so they can verify their peers.
Code: `operator/pkg/tls/certificatemanagement/interface.go` (`TrustedBundle`).
_Avoid_: CA, unqualified

**Truth namespace**:
The namespace where a key pair's source copy lives, as opposed to the application namespace it is copied into.
Code: `operator/pkg/render/certificatemanagement/certificatemanagement.go`.

**`CertificateManagement` (Installation)**:
The Installation `certificateManagement` setting under which pods obtain certificates through CSRs to a user-run signer instead of the operator CA.
Code: `operator/api/v1/installation_types.go` (`CertificateManagement`).
_Avoid_: certificate manager

### Installation spec and defaults

**Installation**:
The `operator.tigera.io/v1` resource named `default` that declares the desired Calico install. An Installation named `overlay` can be merged over it, and the operator also writes selected fields on shared Calico configuration resources.
Code: `operator/api/v1/installation_types.go` (`Installation`).
_Avoid_: install CR, the config

**Overlay Installation**:
An Installation named `overlay` whose spec is merged over `default`.
Code: `operator/pkg/controller/utils/utils.go` (`OverlayInstanceKey`).
_Avoid_: override Installation

**Overlay merge**:
The merge of the overlay Installation's spec over the default one.
Code: `operator/pkg/controller/utils/merge.go` (`OverrideInstallationSpec`).
_Avoid_: override

**Recorded defaults**:
The values the operator filled in for unset Installation fields, stored in `status.defaults`.
Code: `operator/api/v1/installation_types.go` (`InstallationStatus`).

**Computed spec**:
The effective Installation spec the operator renders from, which merges the spec with the recorded defaults and the overlay.
Code: `operator/api/v1/installation_types.go` (`InstallationStatus`).
_Avoid_: defaulted spec

**`IPPool` (Installation)**:
An entry of `Installation.spec.calicoNetwork.ipPools`. The IP pool controller turns it into a `projectcalico.org/v3` IPPool.
Code: `operator/api/v1/installation_types.go` (`IPPool`).
_Avoid_: IPPool, unqualified

**Field manager**:
The server-side apply writer that owns declared fields on shared Calico configuration resources such as FelixConfiguration. Each declared field has a conflict policy of `Error`, `Defer` or `Override`.
Code: `operator/pkg/controller/managedfields/fieldmanager.go` (`FieldManager`).
_Avoid_: annotation tracking

**Declaration**:
The set of fields the operator owns on one resource, each with its conflict policy.
Code: `operator/pkg/controller/managedfields/declaration.go`.

### Images

**Image component**:
One deployable image with its name, version, registry and variant, as listed in `components.Component`. A follow-on refactor will rename the type.
Code: `operator/pkg/components/references.go` (`Component`).
_Avoid_: component, unqualified

**Image key**:
The image's own name, used to look up a variant-supplied build of that image.
Code: `operator/pkg/components/imagefor.go` (`ImageFor`).
_Avoid_: component name

**ImageSet**:
A resource named `<variant>-<release>` that pins image digests. The operator resolves it into every component render implementation before rendering.
Code: `operator/api/v1/imageset_types.go` (`ImageSet`).

**Combined calico image**:
The single `calico/calico` image that most Go components run a subcommand of.
Code: `operator/pkg/components/combined.go`.

### Lifecycle and migrations

**Staged teardown**:
The Installation controller's ordered deletion, driven by one finalizer per controller plus `tigera.io/operator-cleanup`, so each feature's objects go before the RBAC they depend on.
Code: `operator/pkg/render/finalizers.go`.
_Avoid_: graceful termination

**Active operator**:
The operator install named in the `active-operator` ConfigMap. Other operator installs stand down.
Code: `operator/pkg/active/active.go`.
_Avoid_: leader (that is leader election)

**`CALICO_API_GROUP` (operator)**:
Setting the `CALICO_API_GROUP` variable on Calico workloads to `crd.projectcalico.org/v1` or `projectcalico.org/v3`.
Code: `operator/pkg/apigroup/apigroup.go`.

**APIService cutover**:
Holding the `projectcalico.org/v3` APIService on its old backend until the replacement is ready. It is not the kube-controllers APIService handover.
Code: `operator/pkg/controller/apiserver/cutover.go`.

**Namespace migration**:
Moving a manifest install from `kube-system` to `calico-system` node by node, gated by the node migration label.
Code: `operator/pkg/controller/migration/namespace_migration.go` (`CoreNamespaceMigration`).

**Node migration label**:
The label `projectcalico.org/operator-node-migration`, set to `pre-operator` or `migrated`, that decides which calico-node runs on a node.
Code: `operator/pkg/controller/migration/namespace_migration.go`.

**Install conversion**:
Building an Installation from an existing manifest install.
Code: `operator/pkg/controller/migration/convert/convert.go` (`Convert`).
_Avoid_: adoption

**Field-ownership migration**:
Moving a configuration resource's field ownership from annotation tracking to server-side apply.
Code: `operator/pkg/controller/managedfields/migrate.go`.

## Words that need a qualifier

| Word | Meanings | Say |
|---|---|---|
| component | A separately running program; a component render implementation (`operator/pkg/render/component.go` (`Component`)); an image component (`operator/pkg/components/references.go` (`Component`)); a status area with its own TigeraStatus (`operator/DESIGN.md`); the Installation `ComponentName` enum (`operator/api/v1/installation_types.go`); image keys (`operator/pkg/render/component.go` (`ComponentNameNode`)); the `app.kubernetes.io/component` label (`operator/pkg/controller/utils/component.go`); a `calico component <name>` subcommand (`cmd/calico/component.go` (`newComponentCommand`)); a workload found in a manifest install (`operator/pkg/controller/migration/convert/components.go`); a UI component, such as Whisker, served through the Calico Ingress Gateway (`operator/pkg/uigateway/uigateway.go` (`Config`)); the `ComponentAvailable` and `ComponentDegraded` status conditions (`operator/api/v1/tigerastatus_types.go`) | Bare "component" means a running program only. Otherwise: component render implementation, image component, status area, image key, workload name, component subcommand, UI component. |
| override | Workload overrides on the Installation; the overlay merge; image override keys; the `Override` conflict policy | "overrides" for workload overrides; "overlay merge", "image key", "`Override` conflict policy". |
| migration | Namespace migration; install conversion; the v1-to-v3 CRD migration; field-ownership migration | The full name each time. |
| manager | Status manager; certificate manager; field manager; the controller-runtime manager | The qualified name each time. |
| ready | `render.Component.Ready()`; TigeraStatus `Ready`, which equals Available; `ReadyToMonitor` on the status manager | "render precondition" for `Ready()`. |
| certificate management | The operator CA (`CertificateManager`); the Installation `certificateManagement` setting; the render `CertificateManagement` component | "operator CA" and "`CertificateManagement` (Installation)". |
| Inputs | `render.Inputs`; `controller.Inputs` | "render inputs" and "controller inputs". |
| IPPool | An entry of `Installation.spec.calicoNetwork.ipPools`; the `projectcalico.org/v3` IPPool | "`IPPool` (Installation)" and "IPPool". |
| UI component | A UI workload that an ingress gateway fronts, such as Whisker | Name the workload. |
