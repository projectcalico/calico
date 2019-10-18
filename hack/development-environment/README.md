# A canonical Development Environment for Calico

This directory takes as input every calico source dependency (See DEVELOPER_GUIDE.md for details on those), and assumes they
are one level above the calico repository.

It then uses vagrant to 

- create a linux vm
- build all calico images from calico/ ecosystem projects
- mounts these into /calico/all
- runs the `make` targets for creating all docker images for calico
- makes calico orchestration files (i.e. calico.yaml)
- installs a quick kubeadm (single node) and sets relevant iptables/swap rules
- installs the new images that were made from your current branch
- smoke tests that all calico containers are running.

# How to use this recipe

- You can use the `vagrant up` command to test that the changes you made to any calico repository wont break CI,
or reproduce a failure in CI.
- You can use `vagrant up` followed by `vagrant ssh` to get into a kube cluster running the exact source of your
calico build.
- You can use the install.sh script as a quick start for your own dev worklow or automation tooling if you are using
your own calico builds in house. 

# What this recipe is not

- This is not a CI system for upstream calico, for that, see the contributor and developer docs.
- This is not a full test suite: It doesnt run any kind of unit or performance tests.  Patches
are welcome to extendt the install.sh with other optional test/make targets, but ideally, the smoke
test for building calico from scratch should be able to run in under 10 minutes, so that it is 
developer friendly.
- 

