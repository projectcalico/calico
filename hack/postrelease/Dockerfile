FROM docker:24

ARG VERSION
ARG FLANNEL_VERSION
ARG OPERATOR_VERSION

ENV VERSION             ${VERSION}
ENV FLANNEL_VERSION     ${FLANNEL_VERSION}
ENV NOSE_PROCESSES      ${NOSE_PROCESSES}
ENV OPERATOR_VERSION    ${OPERATOR_VERSION}

RUN --mount=type=tmpfs,target=/var/cache/apk apk add --update bash python3 python3-dev py3-pip py-setuptools openssl-dev curl jq

RUN mkdir -p /root/.docker /code
COPY config.json /root/.docker/
COPY requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
