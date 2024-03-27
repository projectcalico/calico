# hadolint global ignore=DL3018
FROM docker:24

ARG VERSION
ARG FLANNEL_VERSION
ARG OPERATOR_VERSION
ARG UID

ENV VERSION             ${VERSION}
ENV FLANNEL_VERSION     ${FLANNEL_VERSION}
ENV NOSE_PROCESSES      ${NOSE_PROCESSES}
ENV OPERATOR_VERSION    ${OPERATOR_VERSION}

RUN --mount=type=tmpfs,target=/var/cache/apk apk add --no-cache \
    bash            \
    python3         \
    python3-dev     \
    py3-pip         \
    py3-yaml        \
    py3-pytest      \
    py3-requests    \
    py3-rich        \
    py-setuptools   \
    openssl-dev     \
    curl            \
    jq              \
    yq

RUN mkdir -p /root/.docker /code
COPY config.json /root/.docker/
RUN adduser -D -u ${UID} test_user
USER test_user

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
