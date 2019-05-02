---
title: calicoctl endpoint
canonical_url: 'https://docs.projectcalico.org/v1.6/reference/calicoctl/endpoint'
---

This sections describes the `calicoctl endpoint` commands.

In Calico an endpoint is a virtual interface from a workload (container or
virtual machine) into the Calico network, and workloads may have more than one
endpoint. Calico applies network policy to endpoints.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl endpoint' commands

Run `calicoctl endpoint --help` to display the following help menu for the
calicoctl endpoint commands.

```

Usage:
  calicoctl endpoint show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>]
    [--workload=<WORKLOAD_ID>] [--endpoint=<ENDPOINT_ID>] [--detailed]
  calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [--host=<HOSTNAME>]
    [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]  [<PROFILES>...]
  calicoctl endpoint <ENDPOINT_ID> profile show [--host=<HOSTNAME>]
    [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]

Description:
  Configure or show endpoints assigned to existing containers

Options:
 --detailed                         Show additional information
 --host=<HOSTNAME>                  Filters endpoints on a specific host
 --orchestrator=<ORCHESTRATOR_ID>   Filters endpoints created on a specific orchestrator
 --workload=<WORKLOAD_ID>           Filters endpoints on a specific workload
 --endpoint=<ENDPOINT_ID>           Filters endpoints with a specific endpoint ID

Examples:
    Show all endpoints belonging to 'host1':
        $ calicoctl endpoint show --host=host1

    Add a profile called 'profile-A' to the endpoint a1b2c3d4:
        $ calicoctl endpoint a1b2c3d4 profile append profile-A

    Add a profile called 'profile-A' to the endpoint a1b2c3d4, but faster,
    by providing more specific filters:
        $ calicoctl endpoint a1b2c3d4 profile append profile-A --host=host1 --orchestrator=docker --workload=f9e8d7e6

```

## calicoctl endpoint commands


### calicoctl endpoint show
This command allows the user to view information about Calico endpoints.

This command can be run on any Calico node.

Command syntax:

```
calicoctl endpoint show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>]
  [--workload=<WORKLOAD_ID>] [--endpoint=<ENDPOINT_ID>] [--detailed]

    <HOSTNAME>: Filter endpoint info on a specific host.
    <ORCHESTRATOR_ID>: Filter endpoint info by this orchestrator identifier.
    <WORKLOAD_ID>: Filter endpoint info on a specific workload.
    <ENDPOINT_ID>: Filter endpoint info on a specific endpoint.

    --detailed: Show additional data about each individual endpoint.
```

This command prints information about endpoints with a single row for each
Calico host.  The output includes:

 - Hostname: Host that owns the endpoint(s) in the row.
 - Orchestrator ID: Orchestrator running the workloads.
 - Number of Workloads: Total number workloads on the host.
 - Number of Endpoints: Total number of endpoints on the host.

When the `--detailed` is included, the output contains one row for each Calico
endpoint in use.  The output includes:

 - Hostname: Host that owns the endpoint in the row.
 - Orchestrator ID: Orchestrator running the workloads.
 - Workload ID: ID of the workload containing the endpoint.
 - Endpoint ID: ID of the endpoint.
 - Addresses: IP addresses assigned to the endpoint.
 - MAC: MAC address of the workload's Calico interface.
 - Profiles: Profiles associated with the endpoint.
 - State: State of the endpoint.

Examples:

```
$ calicoctl endpoint show
+----------+-----------------+---------------------+---------------------+
| Hostname | Orchestrator ID | Number of Workloads | Number of Endpoints |
+----------+-----------------+---------------------+---------------------+
|  calico  |      docker     |          5          |          5          |
+----------+-----------------+---------------------+---------------------+

$ calicoctl endpoint show --detailed
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
| Hostname | Orchestrator ID |                           Workload ID                            |           Endpoint ID            |   Addresses    |        MAC        | Profiles | State  |
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
|  calico  |      docker     | 0d01b3f020fcadfd0090fcbbbbef9658acb26f71c1cb812827afafc625c5ae1a | d79123c4784511e5bd1a080027f532f6 | 192.168.1.4/32 | d6:43:59:f7:93:d3 |          | active |
|  calico  |      docker     | 26d5636108f8e46b0b9d663522c26f05e52acecf11bb10104dfbd9047ad502b6 | d50c35bc784511e5bd1a080027f532f6 | 192.168.1.3/32 | 0e:61:2a:84:30:51 |   PROF   | active |
|  calico  |      docker     | 838a52d2809845a1092c9cb0f8ff5a09437339cbd39b597924eaefacbf50b4ae | d0bd03d8784511e5bd1a080027f532f6 | 192.168.0.1/32 | b6:bc:87:55:54:a0 |   PROF   | active |
|  calico  |      docker     | b75d50055975385f0f26ecfc545e91c10a911dbfff4894a03510a617c4b232fc | d2b58ef8784511e5bd1a080027f532f6 | 192.168.1.2/32 | f2:42:82:f6:1f:a4 |   PROF   | active |
|  calico  |      docker     | ccc8d2e81b8ef7d4eeb8634e61ed515da47f7d5d7803f40408af21c002f379db | d9d6c3a0784511e5bd1a080027f532f6 | 192.168.1.5/32 | f6:ed:d8:c5:dd:ac |          | active |
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+

$ calicoctl endpoint show --endpoint=d79123c4784511e5bd1a080027f532f6 --detailed
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
| Hostname | Orchestrator ID |                           Workload ID                            |           Endpoint ID            |   Addresses    |        MAC        | Profiles | State  |
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+
|  calico  |      docker     | 0d01b3f020fcadfd0090fcbbbbef9658acb26f71c1cb812827afafc625c5ae1a | d79123c4784511e5bd1a080027f532f6 | 192.168.1.4/32 | d6:43:59:f7:93:d3 |          | active |
+----------+-----------------+------------------------------------------------------------------+----------------------------------+----------------+-------------------+----------+--------+

```

### calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set)
> NOTE: This command should NOT be used when running Calico with the Docker
> libnetwork driver.  The libnetwork driver manages the security profiles for
> containers.

This command is used to manage policy profiles associated with endpoints.

The command allows you to:
 - append profiles to the end point by adding any passed in profiles to the
 list of profiles already associated with the endpoint
 - remove profiles from the endpoint's list of profiles
 - set a list of profiles that replaces the current list of profiles associated
 with the endpoint.

If you are controlling Calico network policy for Docker containers using the
default networking (i.e. not libnetwork) it is more common to use the
`calicoctl container <CONTAINER> profile (set|append|remove) <PROFILES>`
command, which can be found in the
[`calicoctl container` reference documentation](./container).

This command can be run on any Calico node.

Command syntax:

```shell
calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [--host=<HOSTNAME>]
  [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]  [<PROFILES>...]

    <ENDPOINT_ID>: Endpoint whose profiles you'd like to modify.
    <HOSTNAME>: Host that owns the endpoint.
    <ORCHESTRATOR_ID>: Orchestrator ID that manages the endpoint's workload.
    <WORKLOAD_ID>: ID of workload that contains the endpoint.
    <PROFILES>: One or more profiles to append, remove, or set on the endpoint.
```

The `<ENDPOINT_ID>` uniquely identifies the endpoint.  Although it is not
necessary to include the optional `<HOSTNAME>`, `<ORCHESTRATOR_ID>` and
`<WORKLOAD_ID>` identifiers, this command executes faster and with reduced
load on the etcd datastore when all of the identifiers are specified together.

Examples:

```
$ calicoctl endpoint d79123c4784511e5bd1a080027f532f6 profile set PROF
Profile(s) PROF set.

$ calicoctl endpoint d79123c4784511e5bd1a080027f532f6 profile append WEB
Profile(s) WEB appended.

$ calicoctl endpoint d79123c4784511e5bd1a080027f532f6 profile remove WEB PROF
Profile(s) WEB,PROF removed.

```

### calicoctl endpoint <ENDPOINT_ID> profile show
This command prints the list of the profiles associated with an endpoint.

This command can be run on any Calico node.

Command syntax:

```
calicoctl endpoint <ENDPOINT_ID> profile show [--host=<HOSTNAME>]
  [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]

    <ENDPOINT_ID>: Endpoint whose profiles you'd like to modify.
    <HOSTNAME>: Host that owns the endpoint.
    <ORCHESTRATOR_ID>: Orchestrator ID that manages the endpoint's workload.
    <WORKLOAD_ID>: ID of workload that contains the endpoint.
```

The `<ENDPOINT_ID>` uniquely identifies the endpoint.  Although it is not
necessary to include the optional `<HOSTNAME>`, `<ORCHESTRATOR_ID>` and
`<WORKLOAD_ID>` identifiers, this command executes faster and with reduced
load on the etcd datastore when all of the identifiers are specified together.

Examples:

```
$ calicoctl endpoint d79123c4784511e5bd1a080027f532f6 profile show
+------+
| Name |
+------+
| PROF |
| WEB  |
+------+
```
