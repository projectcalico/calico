# edge is required to get the fix for https://bugs.alpinelinux.org/issues/4451
FROM alpine:edge
MAINTAINER Tom Denham <tom@projectcalico.org>

# The final container is slightly bloated by having the source code
# But it's only a couple of MB (kept down using .dockerignore)
ADD . /code
WORKDIR /code

# Metadata
ARG VCS_URL 
ARG VCS_REF
ARG BUILD_DATE
LABEL org.label-schema.vcs-url=$VCS_URL \
	  org.label-schema.vcs-ref=$VCS_REF \
	  org.label-schema.build-date=$BUILD_DATE \
	  org.label-schema.url="http://projectcalico.org" \
	  org.label-schema.name="Project Calico" \
	  org.label-schema.license="Apache-2.0"

RUN apk -U add python py-setuptools libffi ip6tables ipset iputils yajl && \
    apk add --virtual temp python-dev libffi-dev py-pip alpine-sdk && \
    pip install -e . && \
    apk del temp && rm -rf /var/cache/apk/*
RUN mkdir /etc/calico && echo -e "[global]\nMetadataAddr = None\nLogFilePath = None\nLogSeverityFile = None" >/etc/calico/felix.cfg
CMD ["calico-felix"]
