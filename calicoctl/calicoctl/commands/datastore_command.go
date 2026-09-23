// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/datastore/migrate"
)

func newDatastoreCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "datastore",
		Short: "Calico datastore management",
		Long: `Manage the Calico datastore, including migrating data between datastore types
and rewriting legacy policy names.`,
	}
	cmd.AddCommand(newMigrateCommand())
	cmd.AddCommand(newMigratePolicyNamesCommand())
	return cmd
}

func newMigratePolicyNamesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate-policy-names",
		Short: "Rewrite pre-v3.32 policy names in an etcdv3 datastore to drop the legacy \"default.\" tier prefix",
		Long: `Rewrite pre-v3.32 policy names in an etcdv3 datastore to drop the legacy
"default." tier prefix. Run this once when upgrading an etcdv3-backed cluster
past v3.32 so existing policy names match the current naming scheme.`,
		Example: `  calicoctl datastore migrate-policy-names`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")
			return migrate.MigratePolicyNames(config, allowMismatch)
		},
	}
	addConfigFlag(cmd)
	return cmd
}

func newMigrateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate the contents of an etcdv3 datastore to a Kubernetes datastore",
		Long: `Migrate the contents of an etcdv3 datastore to a Kubernetes datastore. The
subcommands lock the datastore, export its contents to YAML, import them into
Kubernetes, and unlock when done.`,
	}
	cmd.AddCommand(
		newMigrateExportCommand(),
		newMigrateImportCommand(),
		newMigrateLockCommand(),
		newMigrateUnlockCommand(),
	)
	return cmd
}

func newMigrateExportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the contents of the etcdv3 datastore to yaml",
		Long: `Export the contents of an etcdv3 datastore to YAML. This is the first step in
migrating to a Kubernetes datastore; feed the output into datastore migrate
import.`,
		Example: `  calicoctl datastore migrate export > datastore.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")
			return migrate.Export(config, allowMismatch)
		},
	}
	addConfigFlag(cmd)
	return cmd
}

func newMigrateImportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Store and convert yaml of resources into the Kubernetes datastore",
		Long: `Import resources from a YAML export into a Kubernetes datastore. Takes the
output of datastore migrate export and loads it into the Kubernetes-backed
datastore.`,
		Example: `  calicoctl datastore migrate import -f datastore.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			filename, _ := cmd.Flags().GetString("filename")
			return migrate.Import(config, filename)
		},
	}
	addConfigFlag(cmd)
	cmd.Flags().StringP("filename", "f", "", "Filename to use to import resources.")
	return cmd
}

func newMigrateLockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Lock the datastore to prevent changes during migration",
		Long: `Lock the datastore to prevent changes during a migration. Run this before
exporting so nothing changes while the migration is in progress.`,
		Example: `  calicoctl datastore migrate lock`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")
			return migrate.Lock(config, allowMismatch)
		},
	}
	addConfigFlag(cmd)
	return cmd
}

func newMigrateUnlockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "unlock",
		Short:   "Unlock the datastore to allow changes after migration",
		Long:    `Unlock the datastore to allow changes again once a migration is complete.`,
		Example: `  calicoctl datastore migrate unlock`,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, _ := cmd.Flags().GetString("config")
			allowMismatch, _ := cmd.Flags().GetBool("allow-version-mismatch")
			return migrate.Unlock(config, allowMismatch)
		},
	}
	addConfigFlag(cmd)
	return cmd
}
