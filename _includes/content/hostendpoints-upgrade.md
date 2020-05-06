## Host Endpoints

> **Important**: If your cluster has host endpoints with `interfaceName: *` you must prepare your cluster before
> upgrading. Failure to do so will result in an outage.
{: .alert .alert-danger}

In versions of {{site.prodname}} prior to v3.14, all-interfaces host endpoints (host endpoints with `interfaceName: *`) only supported pre-DNAT policy.
The default behavior of all-interfaces host endpoints, in the absence of any policy, was to allow all traffic.

Beginning from v3.14, all-interfaces host endpoints support normal policy in addition to pre-DNAT policy.
The support for normal policy includes a change in default behavior for all-interfaces host endpoints: in the absence of policy the default behavior
is to **drop traffic**. This default behavior is consistent with "named" host endpoints (which specify a named interface such as "eth0"); named host endpoints
drop traffic in the absence of policy.

Before upgrading to {{page.version}}, you must ensure that global network policies are in place that select existing all-interfaces host endpoints and
explicitly allow existing traffic flows. As a starting point, you can create an allow-all policy that selects existing all-interfaces host endpoints.
First, we'll add a label to the existing host endpoints. Get a list of the nodes that have an all-interfaces host endpoint:

```bash
calicoctl get hep -owide | grep '*' | awk '{print $2}'
```

Example output of this might be:
```
$$ calicoctl get hep -owide | grep '*' | awk '{print $2}'
ip-172-16-101-179.us-west-2.compute.internal
ip-172-16-101-184.us-west-2.compute.internal
ip-172-16-101-192.us-west-2.compute.internal
ip-172-16-101-206.us-west-2.compute.internal
ip-172-16-102-60.us-west-2.compute.internal
```

With the node names, we can label each node with a new label (for example, **host-endpoint-upgrade: ""**):

```bash
calicoctl get hep -owide | grep '*' | awk '{print $2}' | xargs -I {} kubectl label node {} host-endpoint-upgrade=
```

Example output of the above command:

```
$ calicoctl get hep -owide | grep '*' | awk '{print $2}' | xargs -I {} kubectl label node {} host-endpoint-upgrade=
node/ip-172-16-101-179.us-west-2.compute.internal labeled
node/ip-172-16-101-184.us-west-2.compute.internal labeled
node/ip-172-16-101-192.us-west-2.compute.internal labeled
node/ip-172-16-101-206.us-west-2.compute.internal labeled
node/ip-172-16-102-60.us-west-2.compute.internal labeled
```

Now that the nodes with an all-interfaces host endpoint are labeled, we can create a policy to log and whitelist all traffic temporarily:

```bash
cat > allow-all-upgrade.yaml <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-all-upgrade
spec:
  selector: has(host-endpoint-upgrade)
  types:
  - Ingress
  - Egress
  ingress:
  - action: Log
  - action: Allow
  egress:
  - action: Log
  - action: Allow
EOF
```

Apply the policy:

```bash
calicoctl apply -f - < allow-all-upgrade.yaml
```

After applying this policy, all-interfaces host endpoints will log and allow all traffic through them.
This policy will allow all traffic not accounted for by other policies
After upgrading, please review syslog logs for traffic going through the host endpoints and update the policy as needed to secure access to the host endpoints.

### Migrating to auto host endpoints

> **Important**: Auto host endpoints have an allow-all profile attached which allows all traffic in the absence of network policy.
{: .alert .alert-warning}

In order to migrate existing all-interfaces host endpoints to {{site.prodname}}-managed auto host endpoints:

- Add labels from existing host endpoints to {{include.orch}} nodes
- Enable auto host endpoints: new all-interfaces host endpoints are created that have all node labels (including the ones just added)
- Delete old host endpoints

