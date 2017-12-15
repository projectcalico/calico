---
title: Troubleshooting migration and upgrade errors
no_canonical: true
---

## Downgrading

Under some circumstances, you may need to perform a downgrade and reverse
back out of the migration/upgrade process.

You do _not_ need to downgrade if:

- You only ran `calico-upgrade dry-run`.

- You ran `calico-upgrade start` but didn't upgrade any nodes or orchestrator 
  plugins.
  
Otherwise, review the following.

- If you have started upgrading your nodes/plugins but haven’t run 
  `calico-upgrade complete` then:

   1. Downgrade your nodes and plugins.

   1. Once all nodes are downgraded, run `calico-upgrade abort`.
   
- If you have completed your upgrade then downgrade your nodes and plugins 
  as quickly as possible. There is likely a service outage in this case, and 
  any endpoints created after completing and before downgrading will lose networking.

