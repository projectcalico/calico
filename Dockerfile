FROM ubuntu:14.04

CMD ["/sbin/my_init"]

ENV HOME /root

ADD calico_containers/pycalico/requirements.txt /pycalico/

# Uncomment these lines and comment the section underneath to allow faster
# rebuilds when making changes to the scripts.
# The early scripts take a long time to run but change infrequently so
# putting them on a their own lines allow developers to take advantage of
# Docker's layer caching. The downside is much larger images.
#ADD /image/buildconfig /build/buildconfig
#ADD /image/my_init /build/my_init
#ADD /image/base.sh /build/base.sh
#RUN /build/base.sh
#ADD /image/system_services.sh /build/system_services.sh
#RUN	/build/system_services.sh
#ADD /image/install.sh /build/install.sh
#RUN /build/install.sh
#ADD /image/cleanup.sh /build/cleanup.sh
#RUN	/build/cleanup.sh

# Comment these lines out if using the developer-focused alternative instead.
ADD /image /build
RUN /build/base.sh && \
    /build/system_services.sh && \
    /build/install.sh && \
    /build/cleanup.sh

# Copy in our custom configuration files etc. We do this last to speed up
# builds for developer, as it's thing they're most likely to change.
COPY node_filesystem /
COPY calico_containers/pycalico /calico_containers/pycalico
COPY calico_containers/docker_plugin.py /calico_containers/
