FROM docker:18.09

RUN apk add --update bash python python-dev py2-pip py-setuptools openssl-dev curl jq && \
        rm -rf /var/cache/apk/*

RUN mkdir -p /root/.docker
COPY config.json /root/.docker/
COPY requirements.txt /requirements.txt
COPY *.py /code/
RUN pip install -r /requirements.txt

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
