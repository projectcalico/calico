package pinnedversion

import (
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

type CalicoReleaseVersions struct {
	// Dir is the directory to store the pinned version file.
	Dir string

	ProductVersion      string
	ReleaseBranchPrefix string

	OperatorCfg     OperatorConfig
	OperatorVersion string

	versionFilePath string
}

func (p *CalicoReleaseVersions) GenerateFile() (version.Versions, error) {
	ver := version.New(p.ProductVersion)

	tmplData := &calicoTemplateData{
		BaseDomain:     hashreleaseserver.BaseDomain,
		ProductVersion: p.ProductVersion,
		Operator: registry.Component{
			Version:  p.OperatorVersion,
			Image:    p.OperatorCfg.Image,
			Registry: p.OperatorCfg.Registry,
		},
		ReleaseBranch: fmt.Sprintf("%s-%s", p.ReleaseBranchPrefix, ver.Stream()),
	}

	tmpl, err := template.New("versions").Parse(calicoTemplate)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return nil, err
	}
	p.versionFilePath = PinnedVersionFilePath(p.Dir)
	pinnedVersionFile, err := os.Create(p.versionFilePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pinnedVersionFile.Close() }()
	if err := tmpl.Execute(pinnedVersionFile, tmplData); err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *CalicoReleaseVersions) ImageList() ([]string, error) {
	components, err := RetrieveImageComponents(p.Dir)
	if err != nil {
		return nil, err
	}
	componentNames := make([]string, 0, len(components))
	for _, component := range components {
		if component.Image == registry.TigeraOperatorImage {
			continue
		}
		componentNames = append(componentNames, strings.TrimPrefix(component.Image, calicoImageNamespace))
	}
	return componentNames, nil
}

func (p *CalicoReleaseVersions) FlannelVersion() (string, error) {
	versions, err := retrievePinnedVersion(p.Dir)
	if err != nil {
		return "", err
	}
	return versions.Components["flannel"].Version, nil
}
