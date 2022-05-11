# A canonical Development Environment for Calico.

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

## How to use the Kind Recipe (Recommended)

Options:

	- BUILD_CALICO: if "false", won't compile all the source before deploying.
	- ROOT_CALICO_REPOS_DIR: the place where all your source is stored.

Example:

```
git clone https://github.com/projectcalico/confd.git
git clone https://github.com/projectcalico/calico.git
git clone https://github.com/projectcalico/app-policy
git clone https://github.com/projectcalico/libcalico-go.git 
git clone https://github.com/projectcalico/kube-controllers 
git clone https://github.com/projectcalico/felix 
git clone https://github.com/projectcalico/node
git clone https://github.com/projectcalico/api 
git clone https://github.com/projectcalico/node
git clone https://github.com/projectcalico/calicoctl
git clone https://github.com/projectcalico/cni-plugin
git clone https://github.com/projectcalico/pod2daemon
git clone https://github.com/projectcalico/typha

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

This [kind](https://github.com/kubernetes-sigs/kind) recipe runs locally on a linux box, and builds images + starts a kind cluster.  It will *build* all of calico for you as well, by just running "ROOT_CALICO_REPOS_DIR=/calico_all kind-local-up.sh" .

- Of course, that assumes you've cloned all of the calico repositories into /calico_all.  IF they are somewhere else, that's also fine.  
- Make sure you can run *docker* as the user who starts this script.
- Make sure that you've installed *kind* as well as *kubectl*.  

IF you don't have any of these tools, the Vagrant recipe might be easier for you to adopt, as it will bootstrap your entire machine for you.

## How to use this recipe: Centos

Example:

```
	vagrant up
	echo "play with your cluster for a while..."
	vagrant destroy --force
```

- You can use the `vagrant up` command to test that the changes you made to any calico repository won't break CI,
or reproduce a failure in CI.
- You can use `vagrant up` followed by `vagrant ssh` to get into a kube cluster running the exact source of your
calico build.
- You can use the install.sh script as a quick start for your own dev worklow or automation tooling if you are using
your own calico builds in house. 

# What this recipe is not

- This is not a CI system for upstream calico, for that, see the contributor and developer docs.
- This is not a full test suite: It doesn't run any kind of unit or performance tests.  Patches
are welcome to extendt the install.sh with other optional test/make targets, but ideally, the smoke
test for building calico from scratch should be able to run in under 10 minutes, so that it is 
developer friendly.

