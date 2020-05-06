## Migrating to auto host endpoints

> **Important**: Auto host endpoints have an allow-all profile attached which allows all traffic in the absence of network policy.
> This may result in unexpected behavior and data.
{: .alert .alert-danger}

In order to migrate existing all-interfaces host endpoints to {{site.prodname}}-managed auto host endpoints:

1. Add any labels on existing all-interfaces host endpoints to their corresponding {{include.orch}} nodes. {{site.prodname}} manages labels on automatic host endpoints by syncing
   labels from their nodes. Any labels on existing all-interfaces host endpoints should be added to their respective nodes.
   For example, if your existing all-interface host endpoint for node **node1** has the label **environment: dev**, then you must add that same label to its node:

   ```bash
{%- if include.orch == "OpenShift" %}
   oc label node node1 environment=dev
{%- else %}
   kubectl label node node1 environment=dev
{%- endif %}
   ```

2. Enable auto host endpoints by following the [enable automatic host endpoints how-to guide]({{ site.baseurl }}/security/kubernetes-nodes#enable-automatic-host-endpoints).
   Note that automatic host endpoints are created with a profile attached that allows all traffic in the absence of network policy.

   ```bash
   calicoctl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
   ```
3. Delete old all-interfaces host endpoints. You can distinguish host endpoints managed by {{site.prodname}} from others in several ways. First, automatic host endpoints
   have the label **projectcalico.org/created-by: calico-kube-controllers**. Secondly, automatic host endpoints' name have the suffix **-auto-hep**.

   ```bash
   calicoctl delete hostendpoint <old_hostendpoint_name>
   ```
