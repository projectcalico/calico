---
title: calicoctl version
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/commands/version'
---

This section describes the `calicoctl version` command.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl version' commands

Run `calicoctl version --help` to display the following help menu for the
commands.

```
Usage:
  calicoctl version [--config=<CONFIG>]

Options:
  -h --help             Show this screen.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:
  Display the version of calicoctl.
```

### Example

Use `calicoctl version` to obtain the following data.

{% include {{page.version}}/calicoctl-version.md %}

\* To obtain these values, you must configure `calicoctl`
   [to connect to your datastore](/{{page.version}}/usage/calicoctl/install-and-configuration).

## See also

-  [calicoctl configuration](/{{page.version}}/usage/calicoctl/install-and-configuration)
   for details on configuring `calicoctl` to access the Calico datastore.
