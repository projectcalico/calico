FROM ubuntu:14.04

RUN apt-get update
RUN apt-get install -y python-zmq python-flask python-docopt

ADD plugin.py .
ADD rest.py .
