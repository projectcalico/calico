---
title: Security using Calico Profiles and Policy
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/docker/tutorials/security-using-calico-profiles-and-policy'
---

## Background

With Calico as a Docker network plugin, Calico uses an identically named
[profile]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
to represent each Docker network.  This profile is applied to each container
in that network and the profile is used by Calico to configure access policy
for that container.  The Calico network plugin will automatically create the associated profile if it
does not exist when the container is attached to the network.  By default, the profile contains rules that allow full
egress traffic but allow ingress traffic only from containers within the same
network and no other source.  Custom policy for a network can be configured by
creating in advance, or editing, the profile associated with the Docker network.

There are two ways in which the policy that defines the Docker network can be modified:

1. Modify the profile policy rules.  This policy is applied directly to each container
   in the associated Docker network.  This approach is simple, but not very flexible,
   as the profile must describe the full set of rules that apply to the containers in
   the network.

2. Assign labels to the profile, and define global selector based policy.  The
   (Calico-specific) labels are assigned to containers in the associated Docker network.
   The globally defined policy uses selectors to determine which subset of the policy
   is applied to each container based on their labels.  This approach provides a powerful
   way to group together all of your network Policy, makes it easy to reuse policy in
   different networks, and makes it easier to define policy that extends across
   different orchestration systems that use Calico.

## Managing Calico policy for a network

This section provides a worked examples applying policy using the two approaches
described above.

In both cases we create a Calico-Docker network and use the `calicoctl` tool to
achieve the required isolation.

For the worked examples let's assume that we want to provide the following
isolation between a set of database containers and a set of frontend containers:

-  Frontend containers can only access the Database containers over TCP to port 3306.
   For now we'll assume no other connectivity is allowed to/from the frontend.
-  Database containers have no isolation between themselves (to handle synchronization
   within a cluster).  This could be improved by locking down the port ranges and
   protocols, but for brevity we'll just allow full access between database
   containers.

### a) Policy applied directly by the profile

In this example we apply the policy for containers in both networks just using
profiles.  Each network has associated an identically named profile that consists
of a set of labels and policy rules.  We set the labels and policy rules for each
of the two network profiles to provide the required isolation.

#### a.1 Create the Docker networks

On any host in your Calico / Docker network, run the following commands:

```
docker network create --driver calico --ipam-driver calico-ipam database
docker network create --driver calico --ipam-driver calico-ipam frontend
```

#### a.2 Create the profiles

Create the profiles for each of these networks.

We set labels on each profile indicating the network role, in our case frontend
or database.  Each profile also includes a set of ingress and egress rules and
actions, where each rule can filter packets based on a variety of source or
destination attributes (which includes selector based filtering using label
selection).  The labels and rules are applied directly to each container in the
corresponding network.

The labels themselves are arbitrary key/value pairs, and we have decided here to
use the key `role` indicating the network role and a value of either `frontend`
or `database`.

Use `calicoctl apply` to create or update the profiles:

```
cat << EOF | calicoctl apply -f -
- apiVersion: v1
  kind: profile
  metadata:
    name: database
    labels:
      role: database
  spec:
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
- apiVersion: v1
  kind: profile
  metadata:
    name: frontend
    labels:
      role: frontend
  spec:
    egress:
    - action: allow
      protocol: tcp
      destination:
        selector: role == 'database'
        ports:
        -  3306
EOF
```

The above profiles provide the required isolation between the frontend and database
containers.  This works as follows:

-  Containers in the "database" Docker network are assigned the "database"
   Calico profile.
-  Containers in the "frontend" Docker network are assigned the "frontend"
   Calico profile.
-  Each container in the "database" network inherits the label `role = database`
   from its profile.
-  Each container in the "frontend" network inherits the label `role = frontend`
   from its profile.
-  The "database" profile applies ingress and egress policy:
   -  An ingress rule to allow TCP traffic to port 3306 from endpoints that have
      the label `role = frontend` (i.e. from frontend containers since they are
      the only ones with the label `role = frontend`)
   -  An ingress and egress rule to allow all traffic from and to endpoints that
      have the label `role = database` (i.e. from database containers).
-  The "frontend" profile applies a single egress rule to allow all TCP traffic
   to port 3306 on endpoints that have the label `role = database` (i.e. to
   database containers)

For details on all of the possible match criteria, see the
[profile resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
documentation.

### b) Global policy applied through label selection

The same example can be demonstrated using global selector-based policy.
In this case we use the network profiles to apply labels (as in the previous
example), but define a set of global policy resources that use selectors to
determine which subset of the policy applies to each container based on the
labels applied by the profile.

> The advantage of using this approach is that by sharing the same labels
> across different Docker networks, we can re-use globally defined policy without
> having to re-specify it.

#### b.1 Create the Docker networks

On any host in your Calico / Docker network, run the following commands:

```
docker network create --driver calico --ipam-driver calico-ipam database
docker network create --driver calico --ipam-driver calico-ipam frontend
```

#### b.2 Create the profiles

Create the profiles for each of these networks.

We set labels on each profile indicating the network role, in our case frontend
or database.  The labels are applied directly to each container in the
corresponding network.

As with the previous example we have decided to use the key `role` indicating
the network role and a value of either `frontend` or `database`.  Unlike the
previous, we do not define any policy rules within the profile.

Use `calicoctl apply` to create or update the profiles:

```
cat << EOF | calicoctl apply -f -
- apiVersion: v1
  kind: profile
  metadata:
    name: database
    labels:
      role: database
- apiVersion: v1
  kind: profile
  metadata:
    name: frontend
    labels:
      role: frontend
EOF
```

#### b.3 Create policy

Create the global policy to provide the required network isolation.

Policy resources are defined globally, and like profile includes a set of ingress
and egress rules and actions, where each rule can filter packets based on a variety
of source or destination attributes (which includes selector based filtering using label
selection).

Each policy resource also has a "main" selector that is used to determine which
endpoints the policy is applied to based on the labels applied by the network
profiles.

We can use `calicoctl create` to create two new policies for this:

```
cat << EOF | calicoctl create -f -
- apiVersion: v1
  kind: policy
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
- apiVersion: v1
  kind: policy
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

The above policies provide the same isolation as the previous example.  
This works as follows:

-  Containers in the "database" Docker network are assigned the "database"
   Calico profile.
-  Containers in the "frontend" Docker network are assigned the "frontend"
   Calico profile.
-  Each container in the "database" network inherits the label `role = database`
   from its profile.
-  Each container in the "frontend" network inherits the label `role = frontend`
   from its profile.
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
[policy resource]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
documentation.

## Multiple networks

Whilst the Docker API supports the ability to attach a container to multiple
networks, it is not possible to use this feature of Docker when using the Calico.

However, using the selector-based approach for defining network policy it is
possible to achieve the same effect of overlapping networks but with a far
richer policy set.

Extending the previous example, suppose we introduce another network that is
used for system backups and that we want some of our database containers to be
on both the database network and the backup network (so that they are able to
back up the database).  

One approach for doing this is as follows:

-  Define a new label, say `backup = true` to indicate that a particular
   endpoint should be allowed access to the backup network.
-  Define global policy "backupnetwork" that allows full access between all
   components with the  `backup = true` label.
-  Create a Docker network "backups" for backups and update the associated
   profile to assign the `backup = true` label
-  Create a Docker network "database-backup" for database _and_ backup access,
   and update the associated profile to assign both the `backup = true` and
   `role = database` labels.

For your database containers that also need to be on the backup network, use the
"database-backup" network.  Since containers in this network will have the two
labels assigned to it, they will pick up policy that selects both labels - in
other words they will have the locked down database access plus access to the
backup network.

Obviously, the example of allowing full access between everything on the "backup"
network is probably a little too permissive, so you can lock down the access within
the backup network by modifying the global policy selected by the `backup = true`
label.

## Further Reading

For details on configuring advanced policy using container labels, see
[Security using Docker Labels and Calico Policy]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/security-using-docker-labels-and-calico-policy).
