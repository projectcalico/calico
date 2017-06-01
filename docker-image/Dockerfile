FROM alpine:3.4
MAINTAINER Shaun Crampton <shaun@tigera.io>

# Since our binary isn't designed to run as PID 1, run it via the tini init daemon.
RUN apk add --update tini
ENTRYPOINT ["/sbin/tini", "--"]

# TODO Typha: give it its own config file
ADD felix.cfg /etc/calico/felix.cfg

# Put out binary in /code rather than directly in /usr/bin.  This allows the downstream builds
# to more easily extract the build artefacts from the container.
RUN mkdir /code
ADD bin/calico-typha /code
WORKDIR /code
RUN ln -s /code/calico-typha /usr/bin

# Run Typha by default
CMD ["calico-typha"]
