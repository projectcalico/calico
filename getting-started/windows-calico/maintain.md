---
title: Start and stop Calico for Windows services
description: Tasks to manage Calico services and uninstall Calico for Windows.
canonical_url: '/getting-started/windows-calico/maintain'
---

### Big picture

Start, stop, and update {{site.prodNameWindows}} services on the Linux master node, and uninstall for {{site.prodNameWindows}}.

### How to

#### Start and stop {{site.prodNameWindows}} services

- Install and boot {{site.prodNameWindows}}: `install-calico.ps1` 
- Start {{site.prodNameWindows}} services:`start-calico.ps1` 
- Stop {{site.prodNameWindows}} services: `stop-calico.ps1`

#### Update {{site.prodname}} services

To change the parameters defined in `config.ps1`:

- Run `uninstall-calico.ps1` to remove {{site.prodNameWindows}} service configuration
- Modify the configuration
- Run `install-calico.ps1`to reinstall {{site.prodNameWindows}}.

Because `config.ps1` is imported by the various component startup scripts, additional environment variables can be added, as documented in the [{{site.prodname}} reference guide]({{site.baseurl}}/reference).

#### Update service wrapper configuration

The `nssm` command supports changing a number of configuration options for the {{site.prodname}} services. For example, to adjust the maximum size of the Felix log file before it is rotated: 

```
PS C:\... > nssm set TigeraFelix AppRotateBytes 1048576
```

#### Uninstall {{site.prodNameWindows}} from Windows nodes

The following steps removes {{site.prodNameWindows}} (for example to change configuration), but keeps the cluster running.

1. Remove all pods from the Windows nodes.
1. On each Windows node, run the uninstall script:
   ```
   PS C:\CalicoWindows > .\uninstall-calico.ps1
   ```
   >**Note**: If you are uninstalling to change configuration, make sure that you run the uninstall script with the old configuration file.
{: .alert .alert-info}

#### Uninstall kubelet and kube-proxy services from Windows nodes

The following steps uninstall kubelet/kube-proxy services if they were installed by running `C:\CalicoWindows\kubernetes\install-kube-services.ps1`.

1. Remove all pods from the Windows nodes.
1. On each Windows node, run the uninstall script:
   ```
   PS C:\CalicoWindows\kubernetes > .\uninstall-kube-services.ps1
   ```
   
1. If desired, delete the `CalicoWindows` directory.
