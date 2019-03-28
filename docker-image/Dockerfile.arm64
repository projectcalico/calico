ARG QEMU_IMAGE=calico/go-build:latest
FROM ${QEMU_IMAGE} as qemu

FROM arm64v8/debian:9.8-slim as base
MAINTAINER Shaun Crampton <shaun@tigera.io>

# Enable non-native builds of this image on an amd64 hosts.
# This must before any RUN command in this image!
# we only need this for the intermediate "base" image, so we can run all the apt-get and other commands
# and this is only because of using older kernels
# when running on a kernel >= 4.8, this will become less relevant
COPY --from=qemu /usr/bin/qemu-aarch64-static /usr/bin/

# Since our binary isn't designed to run as PID 1, run it via the tini init daemon.
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-arm64 /sbin/tini
RUN chmod +x /sbin/tini

FROM scratch
COPY --from=base /sbin/tini /sbin/tini

# Put our binary in /code rather than directly in /usr/bin.  This allows the downstream builds
# to more easily extract the build artefacts from the container.
ADD bin/calico-typha-arm64 /code/calico-typha
ADD typha.cfg /etc/calico/typha.cfg

WORKDIR /code
ENV PATH "$PATH:/code"

# Run Typha by default
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["calico-typha"]
