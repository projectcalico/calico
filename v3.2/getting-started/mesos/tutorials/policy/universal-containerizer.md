---
title: Network Policy (Universal Containerizer)
redirect_from: latest/getting-started/mesos/tutorials/policy/universal-containerizer
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/tutorials/policy/universal-containerizer'
---

This document will demonstrate how to manipulate policy for {{site.prodname}} using
[Policies]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy). Specifically, we will:

- Set labels on our workload at launch
- Configure policy based off these labels

To demonstrate this, we will use Marathon to launch an nginx webserver using the Universal Containerizer.
Then, we will launch basic curl task which will repeatedly curl the webserver.

> **Note**: This example assumes you are running in a DC/OS environment 
> since it uses the DC/OS DNS to access the web server. It is easy enough 
> to adjust this demo for non-DC/OS environments by replacing the
> `webserver.marathon.containerip.dcos.thisdcos.directory` DNS name with 
> the IP address of the web server container.
{: .alert .alert-info}

## Setting Labels

When launching tasks, assign arbitrary `labels` in the task's `ipAddress` field.
These labels will be passed to {{site.prodname}}'s CNI plugin which will store them in the
Labels field of the corresponding
[workload endpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint#definitions).

```json
{
  "id": "webserver",
  "container": {
    "type": "MESOS",
    "docker": {
      "image": "nginx"
    }
  },
  "ipAddress": {
      "networkName": "calico",
      "labels": {
        "role": "webserver",
        "deployment": "production",
        "tenant": "3"
      }
  },
  "cpu": 0.25
}
```

```json
{
  "id": "client",
  "cmd": "while true; do let COUNTER+=1; curl --connect-timeout 1 -s webserver.marathon.containerip.dcos.thisdcos.directory > /dev/null && echo \"(connection $COUNTER succesful)\" || echo \"($COUNTER timed out)\"; sleep 1; done",
  "ipAddress": {
      "networkName": "calico",
      "labels": {
        "role": "client",
        "deployment": "production",
        "tenant": "3"
      }
  },
  "cpu": 0.25
}
```

Upon launching this application, the task's logs should repeatedly show `(connection succesful)`
as the Default Profile will allow this connection.

## Configuring the Default Profile

{{site.prodname}} configures a base profile that applies to any container
_that does not match a policy_. This profile **allows all containers to communicate
with one another**. Therefore, the logs for the client should show repeatedly
successful connections. Connections made from
any Agent besides the one running the task will fail.

For the purposes of this demo, we will change that default profile to block
incoming requests. This will make it easier to determine when our label-based Policy is
being applied.

Run the following command to block incoming requests in the default Profile:

```yaml
calicoctl apply -f - <<EOF
- apiVersion: projectcalico.org/v3
  kind: Profile
  metadata:
    name: calico
    tags:
    - calico
  spec:
    egress:
    - action: allow
    ingress:
    - action: deny
EOF
```

> **Note**: You'll need `calicoctl` configured to access your central etcd datastore. 
> See [help](/{{page.version}}/reference/calicoctl/setup/etcdv3).
{: .alert .alert-info}

Checking the task's log should show that these connections are no longer successful.

## Configuring Policy

Now that the default profile is isolating our tasks, we will open up the necessary
connections using {{site.prodname}} Policies.

Policy resources are defined globally, and include a set of ingress and egress
rules and actions, where each rule can filter packets based on a variety
of source or destination attributes (which includes selector based filtering
using label selection).

Each policy resource also has a "main" selector that is used to determine which
endpoints the policy is applied to based on the applied labels.

We can use `calicoctl create` to create two new policies for this:

```yaml
calicoctl create -f -<<EOF
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: webserver
  spec:
    order: 0
    selector: role == 'webserver'
    ingress:
    - action: allow
      protocol: tcp
      source:
        selector: role == 'client'
      destination:
        ports:
        -  80
    - action: allow
      source:
        selector: role == 'webserver'
    egress:
    - action: allow
      destination:
        selector: role == 'webserver'
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: client
  spec:
    order: 0
    selector: role == 'client'
    egress:
    - action: allow
      protocol: tcp
      destination:
        selector: role == 'webserver'
        ports:
        -  80
EOF
```

Checking the client's logs should show that it is able to access the container.
Requests from other hosts or tasks with labels that do not match the required
ones will be blocked. This includes Agents that are not running the webserver.
