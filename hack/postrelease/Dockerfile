FROM docker:24

ARG VERSION
ARG FLANNEL_VERSION
ARG OPERATOR_VERSION

ENV VERSION             ${VERSION}
ENV FLANNEL_VERSION     ${FLANNEL_VERSION}
ENV NOSE_PROCESSES      ${NOSE_PROCESSES}
ENV OPERATOR_VERSION    ${OPERATOR_VERSION}

RUN --mount=type=tmpfs,target=/var/cache/apk apk add --no-cache \
    bash=5.2.15-r5                          \
    python3=3.11.4-r0                       \
    python3-dev=3.11.4-r0                   \
    py3-pip=23.1.2-r0                       \
    py-setuptools=py3-setuptools-67.7.2-r0  \
    openssl-dev=3.1.1-r2                    \
    curl=8.1.2-r0                           \
    jq=1.6-r3

RUN mkdir -p /root/.docker /code
COPY config.json /root/.docker/
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
