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

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/datastore"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/datastore/migrate"
)

func newDatastoreCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "datastore",
		Short: "Calico datastore management",
	}
	cmd.AddCommand(newMigrateCommand())
	return cmd
}

func newMigrateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate the contents of an etcdv3 datastore to a Kubernetes datastore",
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return migrate.Export(datastore.BuildMigrateArgs("export", cmd))
		},
	}
	addConfigFlag(cmd)
	return cmd
}

func newMigrateImportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Store and convert yaml of resources into the Kubernetes datastore",
		RunE: func(cmd *cobra.Command, args []string) error {
			return migrate.Import(datastore.BuildMigrateArgs("import", cmd))
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return migrate.Lock(datastore.BuildMigrateArgs("lock", cmd))
		},
	}
	addConfigFlag(cmd)
	return cmd
}

func newMigrateUnlockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the datastore to allow changes after migration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return migrate.Unlock(datastore.BuildMigrateArgs("unlock", cmd))
		},
	}
	addConfigFlag(cmd)
	return cmd
}
