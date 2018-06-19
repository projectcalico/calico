---
title: Installing calicoctl
sitemap: false 
canonical_url: https://docs.projectcalico.org/v3.1/usage/calicoctl/install
---

## About installing calicoctl

`calicoctl` allows you to create, read, update, and delete {{site.prodname}} objects 
from the command line. You can run it on any host with network access to the 
{{site.prodname}} datastore in either of the following formats. 

- [Binary](#installing-calicoctl-as-a-binary): provides full functionality, including
`node` commands for instances of `{{site.nodecontainer}}` on the same host.

- [Container](#installing-calicoctl-as-a-container): provides less functionality than 
the binary format, such as no use of the `node` commands.


## Installing calicoctl as a binary

1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary. 

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example, 
   > `/usr/local/bin/`.
   {: .alert .alert-success}

{% include {{page.version}}/ctl-binary-install.md %}

1. Set the file to be executable.

   ```
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
   
**Next step**:

[Configure `calicoctl` to connect to your datastore](/{{page.version}}/usage/calicoctl/configure/).


## Installing calicoctl as a container

{% include {{page.version}}/ctl-container-install.md %}

**Next step**:

[Configure `calicoctl` to connect to your datastore](/{{page.version}}/usage/calicoctl/configure/).
