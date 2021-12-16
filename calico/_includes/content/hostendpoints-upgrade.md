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
calicoctl get hep -owide | grep '*' | awk '{print $1}'
```

With the names of the all-interfaces host endpoints, we can label each host endpoint with a new label (for example, **host-endpoint-upgrade: ""**):

```bash
calicoctl get hep -owide | grep '*' | awk '{print $1}' \
{%- if include.orch == "OpenShift" %}
  | xargs -I {} oc exec -i -n kube-system calicoctl -- /calicoctl label hostendpoint {} host-endpoint-upgrade=
{%- else %}
  | xargs -I {} kubectl exec -i -n kube-system calicoctl -- /calicoctl label hostendpoint {} host-endpoint-upgrade=
{%- endif %}
```

Now that the nodes with an all-interfaces host endpoint are labeled with **host-endpoint-upgrade**, we can create a policy to log and allow all traffic
going into or out of the host endpoints temporarily:

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
This policy will allow all traffic not accounted for by other policies.
After upgrading, please review syslog logs for traffic going through the host endpoints and update the policy as needed to secure traffic to the host endpoints.
