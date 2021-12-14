# Copyright IBM Corp. 2017
FROM ppc64le/alpine:3.8
MAINTAINER David Wilder <wilder@us.ibm.com>

RUN apk add --no-cache \
    python \
    netcat-openbsd
COPY udpping.sh tcpping.sh responder.py /code/
WORKDIR /code/
RUN chmod +x udpping.sh && chmod +x tcpping.sh
CMD ["python", "responder.py"]
