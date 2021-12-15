# Releasing a new version

We don't typically created tagged releases of libcalico-go.

Versioning is managed through branches. For a given Calico version vX.Y, the corresponding
`release-vX.Y` branch of libcalico-go should be used.

Make sure that each component is updated to the latest commit of the correct release branch
and that tests are passing before peroforming a Calico release.
