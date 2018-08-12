---
title: Security using Docker Labels and Calico Policy
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/tutorials/security-using-docker-labels-and-calico-policy'
---

## Background

With {{site.prodname}} as a Docker network plugin, {{site.prodname}} can be configured to extract the
labels on a container and apply them to the workload endpoint for use with {{site.prodname}}
[policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy).
By default, {{site.prodname}} blocks all traffic unless it has been explicitly allowed
through configuration of the globally
defined policy which uses selectors to determine which subset of the policy is
applied to each container based on their labels.  This approach provides a
powerful way to group together all of your network Policy, makes it easy to
reuse policy in different networks, and makes it easier to define policy that
extends across different orchestration systems that use {{site.prodname}}.

When {{site.prodname}} is configured to use container labels, profiles are not created and 
have no impact on any container traffic.

## Enabling Docker Networking Container Labels Policy

To enable labels to be used in Policy selectors the flag
`--use-docker-networking-container-labels` must be passed when starting
`{{site.nodecontainer}}` with the `calicoctl node run` command.  All `{{site.nodecontainer}}` instances
should be started with the flag to avoid a mix of labels and profiles.

## Managing {{site.prodname}} policy for a network

This section provides an example applying policy using the approach described
above once container labels are enabled.

We create a {{site.prodname}}-Docker network and use the `calicoctl` tool to set policies
that achieve the required isolation and allowances.

For the example let's assume that we want to provide the following isolation
between a set of database containers and a set of frontend containers:

-  Frontend containers can only access the Database containers over TCP to port 3306.
   For now we'll assume no other connectivity is allowed to/from the frontend.
-  Database containers have no isolation between themselves (to handle synchronization
   within a cluster).  This could be improved by locking down the port ranges and
   protocols, but for brevity we'll just allow full access between database
   containers.

### Global policy applied through label selection

This example demonstrates using global selector-based policy with labels
extracted from the Docker containers.

#### 1. Create the Docker network

On any host in your {{site.prodname}} / Docker network, run the following command:

```
docker network create --driver calico --ipam-driver calico-ipam net1
```

#### 2. Create the Labeled Workloads

We set labels on each container indicating the role, in our case frontend
or database.  The labels are applied directly to each container and must be
prefixed with `org.projectcalico.label.` for them to be extracted and applied
to the workload endpoint.

We have decided to use the label `role` indicating the role and a value of
either `frontend` or `database`.  

Create the workloads as docker containers with appropriate labels.

```
docker run --label org.projectcalico.label.role=frontend --net net1 --name frontend-A -tid busybox
docker run --label org.projectcalico.label.role=database --net net1 --name database-A -tid busybox
```

#### 3. Create policy

Create the global policy to provide the required network isolation.

Policy resources are defined globally, and include a set of ingress and egress
rules and actions, where each rule can filter packets based on a variety
of source or destination attributes (which includes selector based filtering
using label selection).

Each policy resource also has a "main" selector that is used to determine which
endpoints the policy is applied to based on the applied labels.

We can use `calicoctl create` to create two new policies for this:

```
cat << EOF | calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: database
  spec:
    order: 0
    selector: role == 'database'
    ingress:
    - action: allow
      protocol: tcp
      source:
        selector: role == 'frontend'
      destination:
        ports:
        -  3306
    - action: allow
      source:
        selector: role == 'database'
    egress:
    - action: allow
      destination:
        selector: role == 'database'
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: frontend
  spec:
    order: 0
    selector: role == 'frontend'
    egress:
    - action: allow
      protocol: tcp
      destination:
        selector: role == 'database'
        ports:
        -  3306
EOF
```

This works as follows:

-  Each database container is given the label `role = database`.
-  Each frontend container in given the label `role = frontend`.
-  The global policy resource "database" uses the selector `role == database` to
   select containers with label `role = database` and applies ingress and egress
   policy:
   -  An ingress rule to allow TCP traffic to port 3306 from endpoints that have
      the label `role = frontend` (i.e. from frontend containers since they are
      the only ones with the label `role = frontend`)
   -  An ingress and egress rule to allow all traffic from and to endpoints that
      have the label `role = database` (i.e. from database containers).
-  The global policy resource "frontend" uses the selector `role == frontend` to
   select containers with label `role = frontend` and applies a single egress
   rule to allow all TCP traffic to port 3306 on endpoints that have the label
   `role = database` (i.e. to database containers)

For details on all of the possible match criteria, see the
[policy resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy)
documentation.

## Multiple networks

While some network providers tend to use multiple networks to enforce
isolation, {{site.prodname}} instead opts to put all containers in the same,
flat network, where they are separated by default, and then connect them using
{{site.prodname}} policy.  For this reason, {{site.prodname}} does not support 
attaching a container to multiple docker networks.

Extending the previous example, suppose we introduce another label that is
used for system backups and that we want some of our database containers to
have the database label and a backup label (so they have database policy and
backup policy applied).

One approach for doing this is as follows:

-  Define a new label, say `backup = true` to indicate that a particular
   endpoint should be allowed access to the backup network.
-  Define global policy "backupnetwork" that allows full access between all
   components with the  `backup = true` label.

For your database containers that also need to be able to access the backup 
endpoints, launch them assigning both the `role = database` and `backup = true`
labels.

```
docker run --label org.projectcalico.label.role=database --label org.projectcalico.label.backup=true --net net1 --name database-B -tid busybox
```

Since containers started like this will have the two labels assigned to them,
they will pick up policy that selects both labels - in other words they will
have the locked down database access plus access to the backup network.

Obviously, the example of allowing full access between everything on the "backup"
network is probably a little too permissive, so you can lock down the access within
the backup network by modifying the global policy selected by the `backup = true`
label.
