---
title: calicoctl node diags
redirect_from: latest/reference/calicoctl/commands/node/diags
---

This section describes the `calicoctl node diags` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) 
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

### Examples

```
$ calicoctl diags
Collecting diags
Using temp dir: /tmp/tmp991ZWu
Dumping netstat output
Dumping routes
Dumping iptables
  - Missing command: ipset
Copying Calico logs
Dumping datastore

Diags saved to /tmp/tmp991ZWu/diags-151015_155032.tar.gz

If required, you can upload the diagnostics bundle to a file sharing service
such as transfer.sh using curl or similar.  For example:

  curl --upload-file /tmp/tmp991ZWu/diags-151015_155032.tar.gz https://transfer.sh/diags-151015_155032.tar.gz
```

### Options

```
  --log-dir=<LOG_DIR>  The directory containing Calico logs.
                       [default: /var/log/calico]
```
