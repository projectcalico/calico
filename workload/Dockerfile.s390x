# The Dockerfile-s390x is copied from node/workload/Dockerfile.
# Modifications done includes:
# 1) Base image has been changed FROM alpine:3.8 to FROM s390x/alpine:3.6
# 2) Maintainer is changed

FROM s390x/alpine:3.6
MAINTAINER LoZ Open Source Ecosystem (https://www.ibm.com/developerworks/community/groups/community/lozopensource)

RUN apk add --no-cache \
    python \
    netcat-openbsd
COPY udpping.sh tcpping.sh responder.py /code/
WORKDIR /code/
RUN chmod +x udpping.sh && chmod +x tcpping.sh
CMD ["python", "responder.py"]
