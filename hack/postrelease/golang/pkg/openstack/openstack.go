package openstack

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

type PackageRevision struct {
	BaseUrl   string
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

func (pr PackageRevision) Get() (*http.Response, error) {
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

type RhelComponent struct {
	Name   string
	Native bool
}

type UbuntuComponent struct {
	Name          string
	ComponentName string
}

var UrlTemplates = map[string]map[string]string{
	"ubuntu": {
		"felix":             "http://ppa.launchpad.net/project-calico/%s/ubuntu/pool/main/f/felix",
		"networking-calico": "http://ppa.launchpad.net/project-calico/%s/ubuntu/pool/main/n/networking-calico",
	},
	"rpm": {
		"x86_64": "http://binaries.projectcalico.org/rpm/%s/x86_64",
		"noarch": "http://binaries.projectcalico.org/rpm/%s/noarch",
	},
}

var dnsmasqVersion string = "2.79_calico1-2"

var (
	ubuntuTemplate  = `{{ .BaseUrl }}/{{ .Component }}_{{ .Version }}-{{ .OSVersion }}_{{ .Arch }}.deb`
	rhelTemplate    = `{{ .BaseUrl }}/{{ .Component }}-{{ .Version }}.{{ .OSVersion }}.{{ .Arch }}.rpm`
	dnsmasqTemplate = `{{ .BaseUrl }}/{{ .Component }}-{{ .Version }}.{{ .OSVersion }}.2.{{ .Arch }}.rpm`
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

var rpmComponents = [...]RhelComponent{
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

var ubuntuComponents = [...]UbuntuComponent{
	// Components filed under 'networking-calico' on the PPA
	{Name: "calico-compute", ComponentName: "networking-calico"},
	{Name: "calico-control", ComponentName: "networking-calico"},
	{Name: "calico-dhcp-agent", ComponentName: "networking-calico"},
	{Name: "networking-calico", ComponentName: "networking-calico"},
	// Components filed under 'felix' on the PPA
	{Name: "calico-common", ComponentName: "felix"},
	{Name: "calico-felix", ComponentName: "felix"},
}

func GetPackages(releaseStream string) []PackageRevision {
	var ppaVersion string = strings.Replace(releaseStream[0:5], "v", "calico-", 1)
	var calicoComponentVersion string = strings.Replace(releaseStream, "v", "", 1)

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

	packageList := make([]PackageRevision, 0)

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
					BaseUrl:   fmt.Sprintf(UrlTemplates["rpm"][arch], ppaVersion),
					Component: rpmComponent.Name,
					Version:   componentVersion,
					OSVersion: rhelVersion,
					Arch:      arch,
					Template:  template,
				}
				packageList = append(packageList, component)
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
				BaseUrl:   fmt.Sprintf(UrlTemplates["ubuntu"][ubuntuComponent.ComponentName], ppaVersion),
				Component: ubuntuComponent.Name,
				Version:   calicoComponentVersion,
				OSVersion: ubuntuVersion,
				Arch:      arch,
				Template:  ubuntuTmpl,
			}
			packageList = append(packageList, component)
		}
	}

	return packageList
}
