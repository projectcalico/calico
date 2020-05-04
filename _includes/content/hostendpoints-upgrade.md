## Host Endpoints

> **Important**: If your cluster has host endpoints with `interfaceName: *` you must prepare your cluster before
> upgrading. Failure to do so will result in an outage.
{: .alert .alert-danger}

In previous versions of {{site.prodname}}, all-interfaces host endpoints (host endpoints with `interfaceName: *`) only supported pre-DNAT policy.
The default behavior of all-interfaces host endpoints, in the absence of any policy, was to allow all traffic.

In {{page.version}}, all-interfaces host endpoints support normal policy in addition to pre-DNAT policy.
The support for normal policy includes a change in default behavior for all-interfaces host endpoints: in the absence of policy the default behavior
is to **drop traffic**. This default behavior is consistent with "named" host endpoints (which specify a named interface such as "eth0"); named host endpoints
drop traffic in the absence of policy.

Before upgrading to {{page.version}}, you must ensure that global network policies are in place that select existing all-interfaces host endpoints and
explicitly allow existing traffic flows.


### Migrating to auto host endpoints

> **Important**: Auto host endpoints have an allow-all profile attached which allows all traffic in the absence of network policy.
{: .alert .alert-warning}

In order to migrate existing all-interfaces host endpoints to {{site.prodname}}-managed auto host endpoints:

- Add labels from existing host endpoints to {{include.orch}} nodes
- Enable auto host endpoints: new all-interfaces host endpoints are created that have all node labels (including the ones just added)
- Delete old host endpoints

