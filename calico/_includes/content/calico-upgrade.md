
> **Important**: Once you begin the migration, stop using `calicoctl` or 
> otherwise modifying the etcdv2 datastore. Any changes to etcdv2
> data will not be migrated to the new datastore.
{: .alert .alert-danger}

1. To begin an interactive data migration session, use the `start` command. While 
   existing connectivity will continue as before, you cannot add any new endpoints 
   until the migration and upgrade complete.

   **Syntax**
   ```
   calico-upgrade[-darwin-amd64|-windows-amd64.exe] start [--apiconfigv1 path/file] [--apiconfigv3 path/file]
   ```
   
   **Reference**
   
   | Flag | Discussion 
   | ---- | ---------- 
   | <code>&#8209;&#8209;apiconfigv1</code> | By default, `calico-upgrade` looks for the etcdv2 configuration file at `/etc/calico/apiconfigv1.cfg`. If you have a configuration file in a different location or if it has a different name, include the `--apiconfigv1` flag and specify the name and location of the file. If you are using environment variables, you don't need this flag.
   | <code>&#8209;&#8209;apiconfigv3</code> | By default, `calico-upgrade` looks for the etcdv3 configuration file at `/etc/calico/apiconfigv3.cfg`. If you have a configuration file in a different location or if it has a different name, include the `--apiconfigv3` flag and specify the name and location of the file. If you are using environment variables, you don't need this flag.
   
   **Example**
   ```
   calico-upgrade start --apiconfigv1 etcdv2.yaml --apiconfigv3 etcdv3.yaml
   ```

1. Check the generated reports for details of conversions.

   - **Errors**: If the `start` command returns one or more errors, review the 
     logs carefully. If it fails partway through, it will attempt to abort the
     process. In rare circumstances, such as due to transient connectivity
     issues, it may be unable to abort. In this case, it may instruct you to
     manually run the `calico-upgrade abort` command.

   - **Failures**: If the migration fails to complete, the etcdv3 datastore may
     contain some of your data. This will cause future attempts to run the 
     `calico-upgrade start` command to fail. You must either [manually remove this 
     data from the etcdv3 datastore](./delete) 
     before trying again or include the `--ignore-v3-data` flag with the 
     `calico-upgrade start` command.
     
## Next steps

Once you have succeeded in migrating your data from etcdv2 to etcdv3, continue 
to [Upgrading](./upgrade).
