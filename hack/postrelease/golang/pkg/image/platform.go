package image

import (
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var expected_linux_platforms = []ocispec.Platform{
	{Architecture: "amd64", OS: "linux", OSVersion: "", OSFeatures: nil, Variant: ""},
	{Architecture: "arm64", OS: "linux", OSVersion: "", OSFeatures: nil, Variant: ""},
	{Architecture: "s390x", OS: "linux", OSVersion: "", OSFeatures: nil, Variant: ""},
	{Architecture: "ppc64le", OS: "linux", OSVersion: "", OSFeatures: nil, Variant: ""},
}

var expected_windows_platforms = []ocispec.Platform{
	{Architecture: "amd64", OS: "windows", OSVersion: "10.0.17763.5696", OSFeatures: nil, Variant: ""},
	{Architecture: "amd64", OS: "windows", OSVersion: "10.0.20348.2402", OSFeatures: nil, Variant: ""},
}
