# calicoctl glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `calicoctl/calicoctl/`.

## Building blocks

The top layer of calicoctl.

| Building block | Code | Responsible for |
|---|---|---|
| Root command | `calicoctl/calicoctl/commands/command.go` (`NewCommand`) | Registers the CRUD commands and the `ipam`, `node`, `datastore` and `cluster` command groups. |
| ResourceManager | `calicoctl/calicoctl/resourcemgr/resourcemgr.go` (`ResourceManager`) | Per-kind create, read, update and delete, table printing and metadata merge over the libcalico-go v3 client. |
| Client manager | `calicoctl/calicoctl/commands/clientmgr/client.go` (`NewClient`) | Builds the v3 client and the backend client from `/etc/calico/calicoctl.cfg` or environment variables. |
| Datastore migrate commands | `calicoctl/calicoctl/commands/datastore/migrate/export.go` (`Export`) | The export, import, lock and unlock steps of the etcd-to-KDD migration. |
| IPAM commands | `calicoctl/calicoctl/commands/ipam_command.go` | The `check`, `release`, `show`, `split` and `configure` subcommands. |
| Version mismatch check | `calicoctl/calicoctl/commands/common/version_mismatch.go` (`CheckVersionMismatch`) | Refuses to run against a cluster whose Calico version differs, unless overridden. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Datastore lock](../GLOSSARY.md#datastore-lock)
- [etcd-to-KDD migration](../GLOSSARY.md#etcd-to-kdd-migration)
- [Policy name migration](../GLOSSARY.md#policy-name-migration)

**ResourceManager**:
The per-kind adapter that gives calicoctl commands create, read, update and delete operations, table headings and templates for one resource kind.
Code: `calicoctl/calicoctl/resourcemgr/resourcemgr.go` (`ResourceManager`).
_Avoid_: resource helper (that is the implementation type)

**Migrate export**:
The step that writes an etcdv3 datastore to a YAML export file, holding its v3 resources and IPAM data plus the cluster GUID.
Code: `calicoctl/calicoctl/commands/datastore/migrate/export.go` (`Export`).
_Avoid_: datastore migration (say etcd-to-KDD migration)

**Migrate import**:
The step that reads the export file and loads it into the Kubernetes datastore.
Code: `calicoctl/calicoctl/commands/datastore/migrate/import.go` (`Import`).
_Avoid_: datastore migration (say etcd-to-KDD migration)

**Version mismatch**:
The condition where a cluster's ClusterInformation `CalicoVersion` differs from calicoctl's own version.
Code: `calicoctl/calicoctl/commands/common/version_mismatch.go` (`CheckVersionMismatch`).
_Avoid_: version skew

**IPAM commands**:
The `calicoctl ipam` subcommand group for inspecting and changing IPAM state, from the integrity report of `check` to the pool `split`.
Code: `calicoctl/calicoctl/commands/ipam_command.go`.
_Avoid_: IPAM GC (that is the kube-controllers code, not these commands)
