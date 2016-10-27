---
title: calicoctl node diags
---

This section describes the `calicoctl node diags` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node diags' command

Run `calicoctl node diags --help` to display the following help menu for the 
calicoctl diags command.

```
Usage:
  calicoctl node diags [--log-dir=<LOG_DIR>]

Options:
  -h --help               Show this screen.
     --log-dir=<LOG_DIR>  The directory containing Calico logs [default: /var/log/calico]

Description:
  Create a diagnostics bundle for the Calico node instance running on this compute host.
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

## See also
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/config) for details on configuring `calicoctl` to access
   the Calico datastore.
