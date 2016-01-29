docker build -t calico/felix -f Dockerfile .
docker run --privileged --net=host -ti --rm calico/felix calico-felix
