FROM jeanblanchard/alpine-glibc
MAINTAINER Tom Denham <tom@projectcalico.org>

ADD http://www.projectcalico.org/builds/calicoctl .
RUN chmod +x calicoctl

ENTRYPOINT ["./calicoctl"]
