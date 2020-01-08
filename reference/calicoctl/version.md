---
title: calicoctl version
canonical_url: '/reference/calicoctl/version'
---

This section describes the `calicoctl version` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/)
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
{: .no-select-button}

### Example

Use `calicoctl version` to obtain the following data.

{% include content/calicoctl-version.md %}

\* To obtain these values, you must configure `calicoctl`
   [to connect to your datastore](/getting-started/calicoctl/configure/).


## See also

-  [Installing calicoctl]({{ site.baseurl }}/getting-started/calicoctl/install).
