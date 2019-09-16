1. If you are NOT installing on CoreOS, skip to the next step. Otherwise, as `/usr` on CoreOS is readonly, the default
   path of the `flexvol-driver-host` volume will need to be changed to match the path of the `--flex-volume-plugin-dir`
   flag passed to the `kube-controller-manager`.

   For example, before:
   ```yaml
   - name: flexvol-driver-host
       hostPath:
         type: DirectoryOrCreate
         path: /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds
   ```

   After:
   ```yaml
   - name: flexvol-driver-host
       hostPath:
         type: DirectoryOrCreate
         path: /var/lib/kubelet/volumeplugins/nodeagent~uds
   ```
