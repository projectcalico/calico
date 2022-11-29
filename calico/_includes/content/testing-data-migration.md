
To launch a test run of the data migration, use the `dry-run` command.

**Syntax**
```
calico-upgrade[-darwin-amd64|-windows-amd64.exe] dry-run [--output-dir=path/directory] [--apiconfigv1 path/file] [--apiconfigv3 path/file]
```
   
**Reference**
   
| Flag | Discussion 
| ---- | ---------- 
| <code>&#8209;&#8209;output&#8209;dir</code> | By default, `calico-upgrade` creates a directory called `calico-upgrade-report` in the current working directory to store its report files. If you want it to write its files to a different location, include a `--output-dir` flag in your command and specify the alternate path. 
| <code>&#8209;&#8209;apiconfigv1</code> | By default, `calico-upgrade` looks for the etcdv2 configuration file at `/etc/calico/apiconfigv1.cfg`. If you have a configuration file in a different location or if it has a different name, include the `--apiconfigv1` flag and specify the name and location of the file. If you are using environment variables, you don't need this flag. 
| <code>&#8209;&#8209;apiconfigv3</code> | By default, `calico-upgrade` looks for the etcdv3 configuration file at `/etc/calico/apiconfigv3.cfg`. If you have a configuration file in a different location or if it has a different name, include the `--apiconfigv3` flag and specify the name and location of the file. If you are using environment variables, you don't need this flag.
   
**Example**
```
calico-upgrade dry-run --output-dir=temp --apiconfigv1 etcdv2.yaml --apiconfigv3 etcdv3.yaml
```

## Next steps

- If you get the message `Successfully validated v1 to v3 conversion`, continue to
   [Migrate your data](./migrate).

- Otherwise, check the generated reports, resolve any issues that are causing
   errors, and run `calico-upgrade dry-run` again.
   
   - **Validation errors**: {{site.prodname}} {{site.data.versions.first.title}}
     features stricter validation than previous versions. For example, it checks that names
     don't exceed the maximum length and that they don't conflict with each other. If you run 
     into an error of this kind, you can change the name as needed and restart the test.
     
   - **Other errors**: if you receive any other errors, especially if they pertain to a 
     workload endpoint, contact Tigera for assistance. 

