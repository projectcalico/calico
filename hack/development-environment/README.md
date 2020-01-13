# A Canonical Development Environment for Calico.

This directory provides a couple of options to create a development environment locally. Options below assume all of the calico source dependencies (see DEVELOPER_GUIDE.md for details on those) are cloned into the same directory, one level above the calico repository.

## How to use the Vagrant Recipe (under /dev-vagrant)

This recipe works for both Linux and Mac users. Vagrant and virtualbox is required.

It uses vagrant to 
- create a Centos vm
- build all calico images from calico/ ecosystem projects
	- by mounting these into /calico/all directory in the Centos vm
	- by running the `make` targets for creating all docker images for calico
	- by running `make` manifests to create calico orchestration files (i.e. calico.yaml)
- installs a quick kubeadm (single node) and sets relevant iptables/swap rules
- installs the new calico images that were made from your current branch
- smoke tests that all calico containers are running.

Example:

```
	cd dev-vagrant
	vagrant up
	echo "play with your cluster for a while..."
	vagrant destroy --force
```

- You can use the `vagrant up` command to test that the changes you made to any calico repository wont break CI,
or reproduce a failure in CI.
- You can use `vagrant up` followed by `vagrant ssh` to get into a kube cluster running the exact source of your
calico build.
- You can use the vagrant-install.sh script as a quick start for your own dev worklow or automation tooling if you are using
your own calico builds in house. 


## How to use the Kind Recipe (under /dev-kind)

This [kind](https://github.com/kubernetes-sigs/kind) recipe runs locally on a linux box. It builds calico locally, creates a kind cluster, and installs calico images to that cluster.
 
- Make sure you can run *docker* as the user who starts this script.
- Make sure that you've installed *kind* as well as *kubectl*.  

If you don't have any of these tools, the Vagrant recipe might be easier for you to adopt, as it will bootstrap your entire machine for you.

Options:

	- BUILD_CALICO: if "false", wont compile all the source before deploying.
	- ROOT_CALICO_REPOS_DIR: the place where all your source is stored.

Example:

```
	ROOT_CALICO_REPOS_DIR=~/calico_all/ BUILD_CALICO=true ./kind-local-up.sh
	echo "play with your cluster for a while"
	kind delete cluster calico-test
```
=======
Example:

```
	ROOT_CALICO_REPOS_DIR=/home/jayunit100/calico_all ./kind-local-up.sh
	echo "play with your cluster for a while"
	kind delete cluster
```

## How to use the Docker Recipe (under /dev-docker)
This recipe works for both Linux and Mac users.

Depending only on Docker, it
- builds and runs a docker container to build calico
- builds calico images and manifests in that container
- starts a kind cluster and installs new calico images.

Options:

	- ROOT_CALICO_REPOS_DIR: the place where all your source is stored.
Example:

```
	ROOT_CALICO_REPOS_DIR=~/calico_all/ ./docker-install.sh
	echo "play with your cluster for a while"
	kind delete cluster calico-test
	docker kill calico-build-container
```
calico-build-container can be useful to rebuild calico images if needed:
```
	docker exec -ti calico-build-container /bin/bash
	cd /calico_all
	make dev-image REGISTRY=calico-dev LOCAL_BUILD=true
```

# What this recipe is not

- This is not a CI system for upstream calico, for that, see the contributor and developer docs.
- This is not a full test suite: It doesn't run any kind of unit or performance tests.  Patches
are welcome to extend the recipes with other optional test/make targets, but ideally, the smoke
test for building calico from scratch should be able to run in under 10 minutes, so that it is 
developer friendly.

