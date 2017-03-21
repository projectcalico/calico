
# Felix FV testing

The tests in this directory test the Felix process as a whole, by running it in
a container, configured to use the Kubernetes datastore driver; driving it by
configuring various resources (pods, policies etc.) in the Kubernetes API; and
verifying or measuring the observable effects.

The test driver is a separate Go program, `k8sfv.test`, that uses the k8s go
client libraries to create, update and delete k8s resources.  It also uses
ginkgo - as our unit tests do - to organize its test cases and specify the
effects to test or measure.  That means, for example, that ginkgo's 'focussing'
can be used to run just a particular test or group of tests.

(In principle we could equally do all this with the etcd datastore, using
either `calicoctl` or `libcalico-go` to populate the etcd datastore, but we
haven't done that yet.)

## Objectives

High-level objectives of this testing are:

- to provide reproducible measurements of Felix's occupancy, when handling
  certain load patterns

- to simulate patterns of Felix load that occur in our system testing,
  especially where the observed performance in handling that load has not been
  initially satisfactory

- to test the scalability of the Felix calculation graph - on which more below.

The calculation graph is the dataplane-independent part of Felix whose input is
the whole Calico data model, and whose output is everything that Felix needs to
program on the local host, comprising:

- the set of active local endpoints, both workload and host, including the
  ordered profile and policy IDs that need to be applied for each of those
  endpoints (WorkloadEndpointUpdate, WorkloadEndpointRemove,
  HostEndpointUpdate, HostEndpointRemove)

- the definition of each locally needed profile and policy, using IP set IDs to
  represent arbitrary sets of IP addresses, where a profile or policy
  (implicitly) uses those (ActivePolicyUpdate, ActivePolicyRemove,
  ActiveProfileUpdate, ActiveProfileRemove)

- the definition of the current set of IP addresses for each IP set ID
  (IPSetDeltaUpdate, IPSetUpdate, IPSetRemove)

- where IP-in-IP routes are needed to reach other compute hosts
  (HostMetadataUpdate, HostMetadataRemove)

- where IP masquerading is needed for outgoing endpoint data (IPAMPoolUpdate,
  IPAMPoolRemove).

(The names in brackets here are those of the protobuf messages that carry the
corresponding information from the calculation graph to the dataplane.)

## Design for Felix calculation graph testing

When using the Kubernetes datastore, the possible inputs into the calculation
graph are narrowed to the endpoint-related state that can be fed into Felix
through the Kubernetes API server.  This means that the interesting inputs
become:

- k8s namespaces (each of which gets mapped to a Calico profile and a policy)

- k8s pods (which get mapped to Calico workload endpoints)

- k8s network policies (which get mapped to Calico policies)

The interesting outputs are correspondingly streamlined, to:

- the set of active local workload endpoints, including the policy and profile
  IDs for each endpoint (WorkloadEndpointUpdate, WorkloadEndpointRemove)

- active policy, i.e. the definition of each locally needed profile ID and
  policy ID (ActivePolicyUpdate, ActivePolicyRemove, ActiveProfileUpdate,
  ActiveProfileRemove)

- active IP sets, i.e. the definition of the IP addresses for each IP set ID
  that is referenced by the active policy (IPSetDeltaUpdate, IPSetUpdate,
  IPSetRemove).

Let's consider what inputs can cause each of those outputs to change, and the
complexity of the calculation graph processing involved.

- The set of active local workload endpoints changes when a pod on the local
  host is created, updated or deleted, or when a pod is moved to or from the
  local host.  The processing complexity and effect on the set are 1:1 with the
  k8s pod input.

- The active policy set can change: if a pod is added to this host (if its
  labels match a policy that previously didn't match any other local
  endpoints); or if a pod is deleted from this host (if its labels were the
  only local match for a particular policy); or if a local pod's labels are
  changed such that it matches different policy; or if a local pod's
  namespace's labels are changed such that it matches different policy; or if
  the default deny/allow setting of a local pod's namespace changes; or if the
  content of an active network policy changes; or if the selector of a network
  policy changes so that it changes between active and inactive.

- The active IP sets can change: if an active network policy's rules are
  changed to use different selectors; or if a pod (on any host) is updated and
  has/had labels matching a source selector of an active network policy; or if
  a namespace is updated such that its pods has/had labels matching a source
  selector of an active network policy.

So the possible distinct inputs, are their effects on the outputs, are as
follows.

- Pod added to local host (inc move from remote to local)
  - O(1) WorkloadEndpointUpdate New active local workload endpoint
  - O(`<num defined policies>`) ActivePolicyUpdate If pod labels match policies
    not previously used on this host

- Pod deleted from local host (inc move from local to remote)
  - O(1) WorkloadEndpointRemove Removed active local workload endpoint
  - O(1 or `<num defined policies>`) ActivePolicyRemove If pod labels matched
    policies that are otherwise not needed

- Pod on local host updated (inc changing its namespace name)
  - O(1) WorkloadEndpointUpdate Update content (addrs, policy/profile IDs) for
    local workload endpoint
  - O(`<num defined policies>`) ActivePolicyUpdate If new pod labels match
    policies not previously used on this host
  - O(1 or `<num defined policies>`) ActivePolicyRemove If old pod labels
    matched policies that are otherwise not needed

- Pod on any host is created or deleted, or has its labels updated
  - O(`<num active policies>` * `<num source selectors in each policy>`)
    IPSetUpdate/DeltaUpdate/Remove to create/update/delete IP sets, if pod
    labels changing.

- Namespace labels updated
  - O(`<num local pods defined in that namespace>`) `<Pod on local host
    updated>`
  - O(`<num pods in namespace>` * `<num active policies>` * `<num source
    selectors in each policy>`) IPSetUpdate/DeltaUpdate/Remove to
    create/update/delete IP sets, if pod labels changing.

- Namespace default deny/allow changed
  - O(`<num local pods defined in that namespace>`) ActivePolicyUpdate to
    change the default for the namespace-policy.

- Network policy selector changed
  - O(`<num active local endpoints>`) WorkloadEndpointUpdate if policy now
    applies, and before didn't, or vice versa.
  - O(`<num active local endpoints>`) `<Active network policy rules changed>`
    if policy didn't apply at all, but now does.
  - O(`<num active local endpoints>`) ActivePolicyRemove if policy now doesn't
    apply at all, but previously did.
  - O(`<num active local endpoints>` + `<num source selectors in policy>`)
    IPSetRemove if policy now doesn't apply at all, but previously did.

- Active network policy rules changed
  - O(1) ActivePolicyUpdate with new rules
  - O(`<num changed source selectors in policy>`)
    IPSetUpdate/DeltaUpdate/Remove to create/update/delete IP sets.

So, some possible tests:

	50 hosts (1 local + 49 remote)
	20 namespaces
	 area=area1/2/3/4/5
	 maturity=production/test/staging/experimental/out-of-service
	50 pods per namespace
	 role=role1/2/3/4/5
	 instance=instance1/2/3/4/5
	 ha=active/backup

    Rotate maturity labels on the namespace, e.g. change all 'production' to
    'out-of-service', then all 'staging' to 'production'.

    Churn pods, i.e. delete and recreate (with same properties), in a ring.

	Create and delete network policies, each with:
	 selector = random set of labels to work on, random ops and values
	 between 1 and 10 rules, each with random source selector (as above) and ports
	Create say 10 of those, then churn by deleting the oldest, making a new one, etc.
