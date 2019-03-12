---
title: Untracked policy
redirect_from: latest/security/host-endpoints/donottrack
canonical_url: 'https://docs.projectcalico.org/v3.6/getting-started/bare-metal/policy/donottrack'
---


Policy for host endpoints can be marked as `doNotTrack`.  This means that rules
in that policy should be applied before any data plane connection tracking, and
that packets allowed by these rules should not be tracked.

Untracked policy is designed for allowing untracked connections to a server
process running directly on a host—where, by 'directly', we mean _not_ in a
pod/VM/container workload.  A typical scenario for using `doNotTrack` policy
would be a server, running directly on a host, that accepts a very high rate of
shortlived connections, such as `memcached`.  On Linux, if those connections
are tracked, the conntrack table can fill up and then Linux may drop packets
for further connection attempts, meaning that those newer connections will
fail.  If you are using {{site.prodname}} to secure that server's host, you can avoid this
problem by defining a policy that allows access to the server's ports and is
marked as `doNotTrack`.

Since there is no connection tracking for a `doNotTrack` policy, it is
important that the policy's ingress and egress rules are specified
symmetrically.  For example, for a server on port 999, the policy must include
an ingress rule allowing access *to* port 999 and an egress rule allowing
outbound traffic *from* port 999.  (Whereas for a connection tracked policy, it
is usually enough to specify the ingress rule only, and then connection
tracking will automatically allow the return path.)

Because of how untracked policy is implemented, untracked ingress rules apply
to all incoming traffic through a host endpoint—regardless of where that
traffic is going—but untracked egress rules only apply to traffic that is
sent from the host itself (not from a local workload) out of that host
endpoint.

