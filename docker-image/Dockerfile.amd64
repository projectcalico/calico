FROM debian:9.8-slim as base
MAINTAINER Shaun Crampton <shaun@tigera.io>

# Since our binary isn't designed to run as PID 1, run it via the tini init daemon.
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-amd64 /sbin/tini
RUN chmod +x /sbin/tini

FROM scratch
COPY --from=base /sbin/tini /sbin/tini

# Put our binary in /code rather than directly in /usr/bin.  This allows the downstream builds
# to more easily extract the build artefacts from the container.
ADD bin/calico-typha-amd64 /code/calico-typha
ADD typha.cfg /etc/calico/typha.cfg

WORKDIR /code
ENV PATH="$PATH:/code"

# Run Typha by default
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["calico-typha"]
