---
title: calicoctl diags
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/calicoctl/commands/node/diags'
---

# User reference for 'calicoctl diags' commands

This section describes the `calicoctl diags` commands.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl diags' commands

Run `calicoctl diags --help` to display the following help menu for the 
calicoctl diags commands.

```

Usage:
  calicoctl diags [--log-dir=<LOG_DIR>]

Description:
  Save diagnostic information

Options:
  --log-dir=<LOG_DIR>  The directory for logs [default: /var/log/calico]

```

## calicoctl diags commands


### calicoctl diags 

This command is used to gather diagnostic information from a Calico node.
This is usually used when trying to diagnose an issue that may be related to
your Calico network.

The output of the command explains how to automatically upload the 
diagnostics to http://transfer.sh for easy sharing of the data. Note that the 
uploaded files will be deleted after 14 days.

This command must be run on the specific Calico node that you are gathering 
diagnostics for.

Command syntax:

```
calicoctl diags [--log-dir=<LOG_DIR>]

  --log-dir=<LOG_DIR>  The directory for logs [default: /var/log/calico]
```

The `--log-dir` flag allows you to specify which directory the Calico logs are 
stored in if the default log directory `/var/log/calico` is not being 
used. The log directory will not be the default if a specific directory was 
passed into the `calicoctl node` command.

Examples:

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
