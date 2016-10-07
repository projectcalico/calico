FROM jeanblanchard/alpine-glibc
MAINTAINER Tom Denham <tom@projectcalico.org>

ADD calicoctl .

ENV CALICO_CTL_CONTAINER=TRUE

ENTRYPOINT ["./calicoctl"]
