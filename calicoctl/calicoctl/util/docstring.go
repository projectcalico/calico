package util

import (
	"os"
	"path/filepath"
	"strings"
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
