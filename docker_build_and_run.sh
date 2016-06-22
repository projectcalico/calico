docker build -t calico/felix -f Dockerfile \
	--build-arg VCS_URL=`git config --get remote.origin.url` \
	--build-arg VCS_REF=`git rev-parse --short HEAD` \
	--build-arg BUILD_DATE=`date -u +"%Y-%m-%dT%H:%M:%SZ"` .
docker run --privileged --net=host -ti --rm calico/felix calico-felix
