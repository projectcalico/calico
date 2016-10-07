FROM jeanblanchard/alpine-glibc
MAINTAINER Tom Denham <tom@projectcalico.org>

# Can be downloaded from //www.projectcalico.org/builds/calicoctl
ADD calicoctl .

ENV CALICO_CTL_CONTAINER=TRUE

ENTRYPOINT ["./calicoctl"]
