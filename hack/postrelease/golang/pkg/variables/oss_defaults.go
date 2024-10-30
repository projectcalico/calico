// Package variables includes functionality for detecting and returning variables for OSS
package variables

import (
	"os"
	"path/filepath"

	"github.com/integralist/go-findroot/find"
)

var (
	tigeraOperatorValuesPath = "charts/tigera-operator/values.yaml"
	calicoValuesPath         = "charts/calico/values.yaml"
)

func getGitRoot() string {
	root, err := find.Repo()
	if err != nil {
		panic(err)
	}
	return root.Path
}

func filePathAtGitRoot(targetFile string) string {
	gitRoot := getGitRoot()
	return filepath.Join(gitRoot, targetFile)
}

// GetOSSDefaults fetches and returns the default configuration variables for OSS Calico
func GetOSSDefaults() {
	// var operatorValues map[string]interface{}

	file, err := os.Open(filePathAtGitRoot(tigeraOperatorValuesPath))
	if err != nil {
		panic(err)
	}
	defer file.Close()
}
