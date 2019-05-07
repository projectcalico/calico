
# Calico packaging

This repo supports building Debian and RPM packages for the current
master of networking-calico, and publishing the RPM packages.

-  To build RPMs: `make rpm`

-  To build Debs: `make deb`

-  To publish RPMs: `./utils/publish-rpms.sh` (with a gcloud identity
   that permits logging into binaries.projectcalico.org)

Still to do:

-  publishing for Debian packages
-  do the same things for Felix
-  support building packages from other possible source code forms, e.g.
   -  a particular point in a Git repo
   -  particular changes in Gerrit
   -  current or past PyPI packages.
-  check ppc64 Dockerfiles against amd64 ones - e.g. the python-pbr install
