---
title: Start and stop Calico for Windows services
description: Tasks to manage Calico services and uninstall Calico for Windows.
canonical_url: '/getting-started/windows-calico/maintain'
---

### Big picture

Start, stop, and update {{site.prodnameWindows}} services on the Linux master node, and uninstall for {{site.prodnameWindows}}.

### How to

#### Start and stop {{site.prodnameWindows}} services

- Install and boot {{site.prodnameWindows}}: `install-calico.ps1`
- Start {{site.prodnameWindows}} services:`start-calico.ps1`
- Stop {{site.prodnameWindows}} services: `stop-calico.ps1`

#### Update {{site.prodname}} services

To change the parameters defined in `config.ps1`:

- Run `uninstall-calico.ps1` to remove {{site.prodnameWindows}} service configuration
- Modify the configuration
- Run `install-calico.ps1`to reinstall {{site.prodnameWindows}}.

Because `config.ps1` is imported by the various component startup scripts, additional environment variables can be added, as documented in the [{{site.prodname}} reference guide]({{site.baseurl}}/reference).

#### Update service wrapper configuration

The `nssm` command supports changing a number of configuration options for the {{site.prodname}} services. For example, to adjust the maximum size of the Felix log file before it is rotated:

```powershell
nssm set CalicoFelix AppRotateBytes 1048576
```

#### Uninstall {{site.prodnameWindows}} from Windows nodes

The following steps removes {{site.prodnameWindows}} (for example to change configuration), but keeps the cluster running.

1. Remove all pods from the Windows nodes.
1. On each Windows node, run the uninstall script:

   ```powershell
   {{site.rootDirWindows}}\uninstall-calico.ps1
   ```
   >**Note**: If you are uninstalling to change configuration, make sure that you run the uninstall script with the old configuration file.
   {: .alert .alert-info}

#### Uninstall kubelet and kube-proxy services from Windows nodes

The following steps uninstall kubelet/kube-proxy services if they were installed by running `{{site.rootDirWindows}}\kubernetes\install-kube-services.ps1`.

1. Remove all pods from the Windows nodes.
1. On each Windows node, run the uninstall script:
   ```
   {{site.rootDirWindows}}\kubernetes\uninstall-kube-services.ps1
   ```

1. If desired, delete the `{{site.rootDirWindows}}` directory.
