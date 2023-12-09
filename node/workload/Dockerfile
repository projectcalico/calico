FROM alpine:3

RUN apk add --no-cache \
    python3 \
    netcat-openbsd

COPY udpping.sh tcpping.sh responder.py /code/

WORKDIR /code/

CMD ["python", "responder.py"]
