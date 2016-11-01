# Releasing a new version
1. After verifying that "master" is good, create a branch with the version name e.g. `git checkout -b v0.4.0`
2. Pin libcalico my making a new commit to that branch, e.g. https://github.com/projectcalico/k8s-policy/commit/4f68aa50beeab47dd8ac5639dcb0dd523d765298
3. Do a clean build (`make clean docker-image`) and then push that docker image e.g. `docker push calico/kube-policy-controller:v0.4.0`
4. Create a release on Github, using github to create a tag from the release branch
5. Delete the release branch.


