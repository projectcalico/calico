"""
calicoctl endpoint --help
Configure the endpoints assigned to existing containers

Usage:
  calicoctl endpoint show [filters...] [--detailed]
  calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [filters...]  [<PROFILES>...]
  calicoctl endpoint <ENDPOINT_ID> profile show [filters...]

Options:
 --detailed  Show additional information
filters     Optional flags which, when used, will speed up the endpoint append/remove/set operatons used by calico,
             or filter endpoints returned by `endpoint show`. See Filters below for valid options.

Filters:
 --host=<HOSTNAME>                   Filters endpoints on a specific host.
 --orchestrator=<ORCHESTRATOR_ID>    Filters endpoints created on a specific orchestrator.
 --workload=<WORKLOAD_ID>            Filters endpoints on a specific workload.
 --endpoint=<ENDPOINT_ID>            Filters endpoints with a specific endpoint ID.

Examples:
    Show all endpoints belonging to 'host1':
        $ calicoctl endpoint show --host=host1

    Add a profile called 'profile-A' to the endpoint a1b2c3d4:
        $ calicoctl endpoint a1b2c3d4 profile append profile-A

    Add a profile called 'profile-A' to the endpoint a1b2c3d4, but faster!
    by providing additional options:
        $ calicoctl endpoint a1b2c3d4 profile append profile-A --host=host1 --orchestrator=docker --workload=f9e8d7e6
"""