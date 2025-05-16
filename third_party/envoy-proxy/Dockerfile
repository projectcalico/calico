# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE
ARG ENVOYBINARY_IMAGE
ARG THIRD_PARTY_REGISTRY
ARG UBI_IMAGE

FROM ${ENVOYBINARY_IMAGE} AS envoybinary

FROM ${UBI_IMAGE} AS ubi

FROM scratch AS source

# dependencies
COPY --from=ubi /bin/sh /bin/sh
COPY --from=ubi /usr/bin/chown /usr/bin/chown
COPY --from=ubi /usr/bin/coreutils /usr/bin/coreutils
COPY --from=ubi /usr/bin/env /usr/bin/env
COPY --from=ubi /usr/bin/id /usr/bin/id
COPY --from=ubi /usr/sbin/groupmod /usr/sbin/groupmod
COPY --from=ubi /usr/sbin/usermod /usr/sbin/usermod

COPY --from=ubi /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=ubi /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=ubi /lib64/libaudit.so.1 /lib64/libaudit.so.1
COPY --from=ubi /lib64/libbz2.so.1 /lib64/libbz2.so.1
COPY --from=ubi /lib64/libcap-ng.so.0 /lib64/libcap-ng.so.0
COPY --from=ubi /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=ubi /lib64/libdl.so.2 /lib64/libdl.so.2
COPY --from=ubi /lib64/libm.so.6 /lib64/libm.so.6
COPY --from=ubi /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=ubi /lib64/librt.so.1 /lib64/librt.so.1
COPY --from=ubi /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=ubi /lib64/libsemanage.so.2 /lib64/libsemanage.so.2
COPY --from=ubi /lib64/libsepol.so.2 /lib64/libsepol.so.2
COPY --from=ubi /lib64/libtinfo.so.6 /lib64/libtinfo.so.6

COPY --from=envoybinary --chown=0:0 --chmod=644 \
    /etc/envoy/envoy.yaml /etc/envoy/envoy.yaml
COPY --from=envoybinary --chown=0:0 --chmod=755 \
    /usr/local/bin/envoy /usr/local/bin/envoy

FROM ${CALICO_BASE}

COPY --from=source / /

EXPOSE 10000
ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml"]
ENV PATH="$PATH:/usr/local/bin"
