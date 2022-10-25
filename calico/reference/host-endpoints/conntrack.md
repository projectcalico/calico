---
title: Connection tracking
description: Workaround for Linux conntrack if Calico policy is not working as it should.
canonical_url: '/reference/host-endpoints/conntrack'
---

{{site.prodname}} uses Linux's connection tracking ('conntrack') as an important
optimization to its processing.  It generally means that {{site.prodname}} only needs to
check its policies for the first packet in an allowed flow—between a pair of
IP addresses and ports—and then conntrack automatically allows further
packets in the same flow, without {{site.prodname}} rechecking every packet.

This can, however, make it look like a {{site.prodname}} policy is not working as it
should, if policy is changed to disallow a flow that was previously allowed.
If packets were recently exchanged on the previously allowed flow, and so there
is conntrack state for that flow that has not yet expired, that conntrack state
will allow further packets between the same IP addresses and ports, even after
the {{site.prodname}} policy has been changed.

Per {{site.prodname}}'s current implementation, there are two workarounds for this:

- Somehow ensure that no further packets flow between the relevant IP
   addresses and ports until the conntrack state has expired (typically about
   a minute).

- Use the 'conntrack' tool to delete the relevant conntrack state; for example
   `conntrack -D -p tcp --orig-port-dst 80`.

Then you should observe that the new {{site.prodname}} policy is enforced for new packets.
