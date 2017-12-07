29 October 2017

This is a pre-release of v3.0.0. This release is intended for testing purposes only and is NOT to be used on production systems.

#### What's new

- Support for the [etcd version 3 datastore](https://coreos.com/blog/etcd3-a-new-etcd.html).

- Two new `calicoctl` resources: [BGP Configuration](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/bgpconfig) and [Felix Configuration](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/felixconfig).

- Those using the Kubernetes API datastore can now use `calicoctl` to create, update, and delete Calico policies.

- The `calicoctl` Policy resource has been split into [Network Policy](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/networkpolicy) and [Global Network Policy](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/globalnetworkpolicy).

- The `get`, `apply`, `create`, `delete`, and `replace` commands of `calicoctl` now include an optional `--namespace=<NS>` flag. Refer to the `calicoctl` [Command reference](https://docs.projectcalico.org/v3.0/reference/calicoctl/commands/) section for more details.

- The `get` command of `calicoctl` now includes an optional `--all-namespaces` flag. Refer to the [calicoctl get](https://docs.projectcalico.org/v3.0/reference/calicoctl/commands/get) section for more information.

- `calicoctl` no longer accepts the following flags in `get` commands: `--node=<NODE>`, `--orchestrator=<ORCH>`, `--workload=<WORKLOAD>`, and `--scope=<SCOPE>`. These options are now a part of the individual resources.

- `calicoctl` no longer includes a `config` command. To achieve the equivalent functionality: refer to [Modifying low-level component configurations](https://docs.projectcalico.org/v3.0/reference/calicoctl/commands/#modifying-low-level-component-configurations).

- You can now name [host](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/hostendpoint#endpointport) and [workload](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/workloadendpoint#endpointport) endpoint ports and reference them by name in your [policy rules](https://docs.projectcalico.org/v3.0/reference/calicoctl/resources/networkpolicy#ports).

- The new `ApplyOnForward` flag allows you to specify if a host endpoint policy should apply to forwarded traffic or not. Forwarded traffic includes traffic forwarded between host endpoints and traffic forwarded between a host endpoint and a workload endpoint on the same host. Refer to [Using Calico to secure host interfaces](https://docs.projectcalico.org/v3.0/getting-started/bare-metal/bare-metal) for more details.

- Calico now works with Kubernetes network services proxy with IPVS/LVS. Calico enforces network policies with kube-proxy running in ipvs mode for Kubernetes clusters. Currently only workload ingress policy is supported.

- After a period of deprecation, this release removes support for the `ETCD_AUTHORITY` and `ETCD_SCHEME` environment variables. Calico no longer reads these values. If you have not transitioned to `ETCD_ENDPOINTS`, you must do so as of v3.0. Refer to [Configuring `calicoctl` - etcdv3 datastore](https://docs.projectcalico.org/v3.0/reference/calicoctl/setup/etcdv3) for more information.



#### Limitations

- **No upgrades**: Calico v3.0.0 ends support for etcd version 2. Existing customers must migrate their data to etcd version 3. The alpha release does not provide migration capabilities, nor does it support upgrades. We plan to add migration and upgrade support in the GA release.

- **Integrates only with Kubernetes and host endpoints**: the OpenStack, OpenShift, Mesos, DC/OS, rkt, and Docker orchestrators have not been tested and are not supported. (Calico v3.0.0 still supports Docker and rkt containers.) We plan to resume support for the OpenStack, OpenShift, Mesos, DC/OS, and Docker orchestrators in a future release.

- **Lack of `calicoctl` data validation**: `calicoctl` does not perform as much validation on data, increasing the potential for bad data. Use caution when entering data via `calicoctl`.

- **BGP route reflector not supported**: large deployments that require the [BGP route reflector](https://docs.projectcalico.org/v3.0/usage/routereflector/bird-rr-config) are not supported. We plan to resume support for the BGP route reflector in a future release.

- **GoBGP not supported**: Setting the `CALICO_NETWORKING_BACKEND` environment variable to `gobgp` is not supported. See [Configuring calico/node](https://docs.projectcalico.org/v3.0/reference/node/configuration) for more information. We plan to resume support for GoBPG in a future release.

<!-- Once migration from etcdv2 to etcdv3 is supported, restore the following warning -->
<!-- <div class="alert alert-danger" role="alert"><b>Important</b>: If you are using the Kubernetes datastore and upgrading from Calico v2.4.x or earlier to Calico v2.5.x or later, you must <a href="https://github.com/projectcalico/calico/blob/master/upgrade/v2.5/README.md">migrate your Calico configuration data</a> before upgrading. Otherwise, your cluster may lose connectivity after the upgrade.</div> -->
