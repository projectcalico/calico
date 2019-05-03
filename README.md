
# Calico packaging

This repo supports building and publishing Debian and RPM packages for
the current master of networking-calico.

-  To build RPMs: `make rpm`

-  To build Debs: `make deb`

-  To publish RPMs: `./utils/publish-rpms.sh`

   -  This is to the 'master' repo; set REPO_NAME for a different
      repo, e.g. `REPO_NAME=calico-3.8 ./utils/publish-rpms.sh`

   -  Also needs GCLOUD_ARGS and HOST set to indicate the RPM host,
      and a gcloud identity that permits logging into that host.

-  To publish Debs: `./utils/publish-debs.sh <SECRET_KEY_FILE>` (with
   `<SECRET_KEY_FILE>` containing the GPG secret key for a member of
   the [Project Calico team on
   Launchpad](https://launchpad.net/~project-calico)

Still to do:

-  do the same things for Felix
-  support building packages from other possible source code forms, e.g.
   -  a particular point in a Git repo
   -  particular changes in Gerrit
   -  current or past PyPI packages.
-  check ppc64 Dockerfiles against amd64 ones - e.g. the python-pbr install
