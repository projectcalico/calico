package util

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
)

func NameAndDescription() (string, string) {
	// Determine name to use in docstring. We want the docstring to change if
	// we're running as a kubectl plugin.
	name := "calicoctl"
	desc := "calicoctl command line tool"
	if strings.HasPrefix(filepath.Base(os.Args[0]), "kubectl-") {
		// We're a kubectl plugin
		name = "kubectl-calico"
		desc = "calico kubectl plugin"
	}
	return name, desc
}

// Resources returns a string to insert into the docstring that lists the valid registered resources in use by
// calicoctl, sorted alphabetically.
func Resources() string {
	kinds := resourcemgr.ValidResources()
	sort.Strings(kinds)
	resourceList := ""
	for _, r := range kinds {
		resourceList += fmt.Sprintf("    - %s\n", strings.ToLower(r))
	}
	return resourceList
}
