---
title: Downgrading Calico
no_canonical: true
---


Under some circumstances, you may need to perform a downgrade and return your
cluster to the previous version of {{site.prodname}}. You may need to do this
before running `calico-upgrade complete` or afterwards. If you need to downgrade 
your cluster after running `calico-upgrade complete`, you should do so as soon
as possible to avoid an outage. Any pods created after `calico-upgrade complete`
and before downgrading will lose networking.

_More docs on this coming soon!_

