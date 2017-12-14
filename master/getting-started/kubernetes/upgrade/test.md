---
title: Testing the data migration
no_canonical: true
---

1. Run `calico-upgrade dry-run` to validate the migration.

   > **Note**: By default, `calico-upgrade` creates a directory called `calico-upgrade-report` 
   > in the current working directory to store its report files. If you want it to write
   > its files to a different location, include a `--output-dir` flag in your command and 
   > specify the alternate path.
   {: .alert .alert-info}

1. If you get the message `Successfully validated v1 to v3 conversion`, continue to
   [Migrate your data](/{{page.version}}/getting-started/kubernetes/upgrade/migrate).

   Otherwise, check the generated reports and resolve any issues that are causing
   errors. In some cases this may require adding and deleting an entry 
   to modify its name (e.g. if the migrated name is too long, or there are 
   clashing names in the migrated config). Once you have resolved the issues, return
   again to step 1 in this procedure. 
   
