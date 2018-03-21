1. Log into the host, open a terminal prompt, and navigate to the location where
you want to install the binary. 

   > **Tip**: Consider navigating to a location that's in your `PATH`. For example, 
   > `/usr/local/bin/`.
   {: .alert .alert-success}

1. Use the following command to download the `calicoctl` binary.

   ```
   curl -O -L {{site.data.versions[page.version].first.components.calicoctl.download_url}}
   ```

1. Set the file to be executable.

   ```
   chmod +x calicoctl
   ```

   > **Note**: If the location of `calicoctl` is not already in your `PATH`, move the file
   > to one that is or add its location to your `PATH`. This will allow you to invoke it
   > without having to prepend its location.
   {: .alert .alert-info}
