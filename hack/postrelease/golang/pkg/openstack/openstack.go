// Package openstack contains functionality for calculating and validating openstack package releases
package openstack

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// PackageRevision represents a package with all its various permutations
type PackageRevision struct {
	BaseURL   string
	Component string
	Version   string
	OSVersion string
	Arch      string
	Template  *template.Template
}

func (pr PackageRevision) toURL() (string, error) {
	buf := &bytes.Buffer{}
	err := pr.Template.Execute(buf, pr)
	return buf.String(), err
}

// Head fetches and returns the HTTP HEAD response for a given PackageRevision
func (pr PackageRevision) Head() (*http.Response, error) {
	url, err := pr.toURL()
	if err != nil {
		panic(fmt.Errorf("could not generate url: %w", err))
	}

	response, err := http.Head(url)
	if err != nil {
		return response, fmt.Errorf("could not fetch url: %w", err)
	}
	return response, err
}

// rhelComponent represents a component which we publish for RHEL
type rhelComponent struct {
	Name   string
	Native bool
}

// ubuntuComponent represents a component which we publish for Ubuntu
type ubuntuComponent struct {
	Name          string
	ComponentName string
}

var urlTemplates = map[string]map[string]string{
	"ubuntu": {
		"felix":             "http://ppa.launchpad.net/project-calico/%s/ubuntu/pool/main/f/felix",
		"networking-calico": "http://ppa.launchpad.net/project-calico/%s/ubuntu/pool/main/n/networking-calico",
	},
	"rpm": {
		"x86_64": "http://binaries.projectcalico.org/rpm/%s/x86_64",
		"noarch": "http://binaries.projectcalico.org/rpm/%s/noarch",
	},
}

var dnsmasqVersion = "2.79_calico1-2"

var (
	ubuntuTemplate  = `{{ .BaseURL }}/{{ .Component }}_{{ .Version }}-{{ .OSVersion }}_{{ .Arch }}.deb`
	rhelTemplate    = `{{ .BaseURL }}/{{ .Component }}-{{ .Version }}.{{ .OSVersion }}.{{ .Arch }}.rpm`
	dnsmasqTemplate = `{{ .BaseURL }}/{{ .Component }}-{{ .Version }}.{{ .OSVersion }}.2.{{ .Arch }}.rpm`
)

var rhelVersions = [...]string{
	"el7",
}

var rpmArches = [...]string{
	"x86_64",
}

var ubuntuVersions = [...]string{
	"focal",
	"jammy",
}

var rpmComponents = [...]rhelComponent{
	// 'Native' components built for their specific architecture
	{Name: "calico-common", Native: true},
	{Name: "calico-felix", Native: true},
	{Name: "felix-debuginfo", Native: true},

	// dnsmasq-related components
	{Name: "dnsmasq", Native: true},
	{Name: "dnsmasq-debuginfo", Native: true},
	{Name: "dnsmasq-utils", Native: true},

	// Non-native components (i.e. 'noarch')
	{Name: "calico-compute", Native: false},
	{Name: "calico-control", Native: false},
	{Name: "calico-dhcp-agent", Native: false},
	{Name: "networking-calico", Native: false},
}

var ubuntuComponents = [...]ubuntuComponent{
	// Components filed under 'networking-calico' on the PPA
	{Name: "calico-compute", ComponentName: "networking-calico"},
	{Name: "calico-control", ComponentName: "networking-calico"},
	{Name: "calico-dhcp-agent", ComponentName: "networking-calico"},
	{Name: "networking-calico", ComponentName: "networking-calico"},
	// Components filed under 'felix' on the PPA
	{Name: "calico-common", ComponentName: "felix"},
	{Name: "calico-felix", ComponentName: "felix"},
}

// GetPackages calculates and returns the expected packages for a given calico release
func GetPackages(releaseStream string) map[string][]PackageRevision {
	ppaVersion := strings.Replace(releaseStream[0:5], "v", "calico-", 1)
	calicoComponentVersion := strings.Replace(releaseStream, "v", "", 1)

	ubuntuTmpl, err := template.New("ubuntuTemplate").Parse(ubuntuTemplate)
	if err != nil {
		panic(err)
	}
	rhelTmpl, err := template.New("rhelTemplate").Parse(rhelTemplate)
	if err != nil {
		panic(err)
	}

	dnsmasqTmpl, err := template.New("dnsmasqTemplate").Parse(dnsmasqTemplate)
	if err != nil {
		panic(err)
	}

	packageList := make(map[string][]PackageRevision, 0)

	for _, rpmArch := range rpmArches {
		for _, rhelVersion := range rhelVersions {
			for _, rpmComponent := range rpmComponents {
				var arch string
				var template *template.Template
				var componentVersion string
				if rpmComponent.Native {
					arch = rpmArch
				} else {
					arch = "noarch"
				}
				if strings.HasPrefix(rpmComponent.Name, "dnsmasq") {
					componentVersion = dnsmasqVersion
					template = dnsmasqTmpl
				} else {
					componentVersion = calicoComponentVersion + "-1"
					template = rhelTmpl
				}
				component := PackageRevision{
					BaseURL:   fmt.Sprintf(urlTemplates["rpm"][arch], ppaVersion),
					Component: rpmComponent.Name,
					Version:   componentVersion,
					OSVersion: rhelVersion,
					Arch:      arch,
					Template:  template,
				}
				packageList["rhel"] = append(packageList["rhel"], component)
			}
		}
	}

	for _, ubuntuComponent := range ubuntuComponents {
		var arch string
		if ubuntuComponent.Name == "calico-felix" {
			arch = "amd64"
		} else {
			arch = "all"
		}

		for _, ubuntuVersion := range ubuntuVersions {
			component := PackageRevision{
				BaseURL:   fmt.Sprintf(urlTemplates["ubuntu"][ubuntuComponent.ComponentName], ppaVersion),
				Component: ubuntuComponent.Name,
				Version:   calicoComponentVersion,
				OSVersion: ubuntuVersion,
				Arch:      arch,
				Template:  ubuntuTmpl,
			}
			packageList["ubuntu"] = append(packageList["ubuntu"], component)
		}
	}

	return packageList
}
