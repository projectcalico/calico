FROM jeanblanchard/alpine-glibc
MAINTAINER Tom Denham <tom@projectcalico.org>

ADD http://www.projectcalico.org/builds/calicoctl .
RUN chmod +x calicoctl

ENV CALICO_CTL_CONTAINER=TRUE

ENTRYPOINT ["./calicoctl"]
