FROM alpine:3.11

RUN apk add --no-cache \
    python \
    netcat-openbsd

COPY udpping.sh tcpping.sh responder.py /code/

WORKDIR /code/

CMD ["python", "responder.py"]
