---
title: Accessing Calico policy with Calico as a network plugin
---

## Background

With Calico as a Docker network plugin, Calico will create an identically named 
[profile]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
to represent each Docker network.  This profile is applied to each container 
in that network and the profile is used by Calico to configure access policy
for that container.  By default, the profile contains rules that allow full
egress traffic but allow ingress traffic only from containers within the same
network and no other source.

> Custom policy for a network can be configured by creating in advance, or editing,
> the profile associated with the Docker network.

There are two ways in which the policy that defines the Docker network can be modified:

-  Modify the profile policy rules.  This policy is applied directly to each container 
   in the associated Docker network.  This approach is simple, but not very flexible, 
   as the profile must describe the full set of rules that apply to the containers in
   the network.
-  Assign labels to the profile, and define global selector based policy.  The 
   (Calico-specific) labels are assigned to containers in the associated Docker network. 
   The globally defined policy uses selectors to determine which subset of the policy 
   is applied to each containers based on their labels.  This approach provides a powerful
   way to group together all of your network Policy, makes it easy to reuse policy in
   different networks and makes it easier to define policy that extends across 
   different orchestration systems that use Calico.

## Managing Calico policy for a network

This section provides a worked examples applying policy using the two approaches
described above.

In both cases we create a Calico-Docker network and use the `calicoctl` tool to
achieve the required isolation.

The example we consider is this:  We want to provide isolation between a set of 
database containers and a set of app containers, allowing only inbound
TCP connections from the app containers to the database containers on
port 3306.  We also want to allow all traffic between database containers.

### Policy applied directly by the profile

An approach, which may be sufficient for certain scenarios is to apply
policy directly through the profile.  In this case we do the following:

-  create two Docker networks, one for apps and the other for databases
-  configure the profiles associated with each network to include:
   -  labels which will be applied to the containers in the network
   -  policy rules which will be applied to the containers in the network.

#### 1. Create the Docker networks

On any host in your Calico / Docker network, run the following commands:

```
docker network create --driver calico --ipam-driver calico-ipam databases 
docker network create --driver calico --ipam-driver calico-ipam apps 
```

#### 2. Create the profiles

Create the profiles for each of these networks.  The profile may contains a set 
of labels and a set of ingress and egress rules and actions where each rule can 
filter packets based on a variety of source or destination attributes (including 
selector based filtering using label selection).  The labels and rules are applied
directly to each container in the corresponding network.  

Use `calicoctl apply` to create or update the profiles:

```
cat << EOF | dist/calicoctl apply -f -
- apiVersion: v1
  kind: profile
  metadata:
    name: databases
    labels:
      role: database
  spec:
    ingress:
    - action: allow
      protocol: tcp
      source:
        selector: role == 'app'
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
    name: apps
    labels:
      role: app
  spec:
    egress:
    - action: allow
EOF
```

The above policy demonstrates profile based policy to lock down the database 
containers.  The policy allows all traffic between database containers, 
and allows inbound TCP connections on port 3306 from app containers.  All 
other traffic to and from the database containers is locked down.  The app 
containers are open to allow all egress traffic.

This works as follows:

-  Containers in the "databases" Docker network are assigned the "databases"
   Calico profile.  Containers in the "apps" Docker network are assigned the 
   "apps" Calico profile.
-  The "databases" profile assigns the Calico label `role = database` to each
   database container.  The "apps" profile assigns the Calico label `role = app`
   to each app container.
-  The "databases" profile assigns ingress and egress policy as follows:
   -  An ingress rule to allow TCP traffic to port 3306 from endpoints that have
      the label `role = app` (i.e. from app containers since they are the only
      ones with the `role = app` assignment)
   -  An ingress and egress rule to allow all traffic from and to endpoints that
      have the label `role = database` (i.e. from database containers).
-  The "apps" profile assigns a single rule to allow all egress traffic.

### Global policy applied through label selection

The same example can be demonstrated using global selector-based policy.
In this case we need to do the following:

-  create two Docker networks, one for apps and the other for databases
-  configure the profiles associated with each network to include labels which
   will be applied to containers in the network
-  create global policy that uses selectors to determine which subset of the 
   policy applies to which container.

> The advantage of using this approach is that by sharing the same labels 
> across different Docker networks, we can re-use globally defined policy without
> having to re-specify it.

#### 1. Create the Docker networks

On any host in your Calico / Docker network, run the following commands:

```
docker network create --driver calico --ipam-driver calico-ipam databases 
docker network create --driver calico --ipam-driver calico-ipam apps 
```

#### 2. Create the profiles

Create the profiles for each of these networks to add a "role" label that
specifies the role of the entities on the network.  Use `calicoctl apply` to 
create or update these profiles:

```
cat << EOF | calicoctl apply -f -
- apiVersion: v1
  kind: profile
  metadata:
    name: databases
    labels:
      role: database
- apiVersion: v1
  kind: profile
  metadata:
    name: apps
    labels:
      role: app
EOF
```

These profiles only contain labels.  The labels will be applied to each container
in the corresponding network.  So, for example, containers in the `databases` 
network will have the Calico label `role = database` applied to them.

#### 3. Create policy

Policy resources are defined globally.  The selector in a policy resource selects which
endpoints the policy applies to based on the Calico labels assigned to each endpoint.
Each policy contains a set of ingress and egress rules and actions where each rule can 
filter packets based on a variety of source or destination attributes (including selector
based filtering using label based selection).

We can use `calicoctl create` to create two new policies for this:

```
cat << EOF | calicoctl create -f -
- apiVersion: v1
  kind: policy
  metadata:
    name: databases
  spec:
    order: 0
    selector: role == 'database'
    ingress:
    - action: allow
      protocol: tcp
      source:
        selector: role == 'app'
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
    name: apps
  spec:
    order: 0
    selector: role == 'app'
    egress:
    - action: allow
EOF
```

The above policy demonstrates globally defined selector based policy to lock 
down the database containers.  It is functionally equivalent to the previous example.
The policy allows all traffic between database containers, and allows inbound 
TCP connections on port 3306 from app containers.  All other traffic to and from 
the database containers is locked down.  The app containers are open to allow all 
egress traffic.

This works as follows:

-  Containers in the "databases" Docker network are assigned the "databases"
   Calico profile.  Containers in the "apps" Docker network are assigned the 
   "apps" Calico profile.
-  The "databases" profile assigns the Calico label `role = database` to each
   database container.  The "apps" profile assigns the Calico label `role = app`
   to each app container.
-  The global policy resource "databases" uses the selector to select which
   containers to apply the policy to - in this case those that have the 
   `role = database` label.  The ingress and egress policy applied to these
   containers is as follows:
   -  An ingress rule to allow TCP traffic to port 3306 from endpoints that have
      the label `role = app` (i.e. from app containers since they are the only
      ones with the `role = app` assignment)
   -  An ingress and egress rule to allow all traffic from and to endpoints that
      have the label `role = database` (i.e. from database containers).
-  The global policy resource "apps" uses the selector to select which
   containers to apply the policy to - in this case those that have the 
   `role = app` label.  The policy applied to these containers is a single rule 
   to allow all egress traffic.

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
-  Create a Docker network "database-backup" for databases _and_ backup access,
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