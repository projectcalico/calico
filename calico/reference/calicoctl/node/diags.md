---
title: calicoctl node diags
description: Command to get diagnostics from a Calico node.
canonical_url: '/reference/calicoctl/node/diags'
---

This section describes the `calicoctl node diags` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node diags' command

Run `calicoctl node diags --help` to display the following help menu for the
command.

```
Usage:
  calicoctl node diags [--log-dir=<LOG_DIR>]

Options:
  -h --help               Show this screen.
     --log-dir=<LOG_DIR>  The directory containing Calico logs
                          [default: /var/log/calico]

Description:
  This command is used to gather diagnostic information from a Calico node.
  This is usually used when trying to diagnose an issue that may be related to
  your Calico network.

  The output of the command explains how to automatically upload the
  diagnostics to http://transfer.sh for easy sharing of the data. Note that the
  uploaded files will be deleted after 14 days.

  This command must be run on the specific Calico node that you are gathering
  diagnostics for.
```
{: .no-select-button}

### Examples

```bash
sudo calicoctl node diags
```

An example response follows.

```
Collecting diagnostics
Using temp dir: /tmp/calico676127473
Dumping netstat
Dumping routes (IPv4)
Dumping routes (IPv6)
Dumping interface info (IPv4)
Dumping interface info (IPv6)
Dumping iptables (IPv4)
Dumping iptables (IPv6)
Dumping ipsets
exit status 1
Dumping ipsets (container)
Copying journal for calico-node.service
Dumping felix stats
Copying Calico logs

Diags saved to /tmp/calico676127473/diags-20170522_151219.tar.gz
If required, you can upload the diagnostics bundle to a file sharing service
such as transfer.sh using curl or similar.  For example:

    curl --upload-file /tmp/calico676127473/diags-20170522_151219.tar.gz https://transfer.sh//tmp/calico676127473/diags-20170522_151219.tar.gz
```
{: .no-select-button}

### Options

```
  --log-dir=<LOG_DIR>  The directory containing Calico logs.
                       [default: /var/log/calico]
```
{: .no-select-button}
