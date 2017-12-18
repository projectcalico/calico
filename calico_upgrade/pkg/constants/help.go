// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package constants

const (
	DatastoreIntro = `Set the Calico datastore access information in the environment variables or
supply details in a config file. If you are using config files, use the v1
format of the config file (--apiconfigv1 param), and the v3 format of the
config (--apiconfigv3 param). If you are using environment variables, the v1
environments are all prefixed with 'APIV1_', for example:
  APIV1_ETCD_ENDPOINTS=http://etcdcluster:2379

`
	Exiting = "Exiting..."

	ReportHelp = `    ` + FileConvertedNames + `
      This contains a mapping between the v1 resource name and the v3 resource
      name. This will contain an entry for every v1 resource that was
      migrated.

    ` + FileNameClashes + `
      This contains a list of resources that after conversion to v3 have
      names that are identical to other converted resources. This may occur
      because name formats in Calico v3 are in some cases more restrictive
      than previous versions. When the migration code modifies a name an
      additional short qualifying suffix is appended. In rare circumstances
      the converted name (with the additional qualifier) may clash with other
      resources of the same kind.

    ` + FileConversionErrors + `
      This contains a list of all of the errors converting the v1 data to
      v3 format. There may be multiple conversion errors for a single
      resource. Provided the v1 format data is correct, conversion errors
      should be rare.

    ` + FilePolicyController + `
      This contains a list of the v1 resources that we are not migrating
      because the name of the resource indicates that the resource is created
      by the policy controller and will automatically be created when the
      policy controller is upgraded.

    ` + FileValidationErrors + `
      This contains a list of errors that occurred when validating the v3
      resources that were otherwise successfully converted from v1. These
      errors may indicate an issue such as a migrated name that is too long
      and would need resolving by deleting/re-adding the resource with a
      shorter name before attempting the upgrade. Or these errors may
      indicate an issue with the migration script itself. If you believe the
      script is at fault, it is recommended to raise a GitHub issue at
         https://github.com/projectcalico/calico/issues
      and await a patch before continuing with the upgrade.
`
)
