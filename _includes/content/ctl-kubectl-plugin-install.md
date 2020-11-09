## Install calicoctl as a kubectl plugin on a single host

1. Log in to the host, open a terminal prompt, and navigate to the location where
you want to install the binary.

   > **Note**: In order to install `{{include.cli}}` as a kubectl plugin, the binary must be located in your `PATH`. For example,
   > `/usr/local/bin/`.
   {: .alert .alert-info}

1. Use the following command to download the `calicoctl` binary.

   ```bash
   curl -o kubectl-calico -L  {% include urls component="calicoctl" %}
   ```

1. Set the file to be executable.

   ```bash
   chmod +x kubectl-calico
   ```

   > **Note**: If the location of `kubectl-calico` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This is required in order for
   > kubectl to detect the plugin and allow you to use it.
   {: .alert .alert-info}

1. Verify the plugin works.

   ```
   kubectl calico -h
   ```

You can now run any `{{include.cli}}` subcommands through `kubectl calico`.

> **Note**: If you run these commands from your local machine (instead of a host node), some of
> the node related subcommands will not work (like node status).
{: .alert .alert-info}

**Next step**:

[Configure `calicoctl` to connect to your datastore](configure).
