---
title: Uninstall Calico for Windows
description: 
canonical_url: 
---

### Big picture

Uninstall the {{site.prodNameWindows}} cluster.

### How to

If are spinning down your cluster, you do not need to complete this procedure. If you want to keep your cluster up, but remove {{site.prodNameWindows}}, follow these steps.

1. Remove all pods from the Windows nodes.
1. On each Windows node, run the uninstall script:

   ```
   PS C:\TigeraCalico > .\uninstall-calico.ps1
   ```
   >**Note**: If you are uninstalling to change configuration, make sure that you run the uninstall
script with the old configuration file.
{: .alert .alert-info}

1. If desired, delete the `TigeraCalico` directory.
1. To remove the Linux component, ask your support representative for instructions.
