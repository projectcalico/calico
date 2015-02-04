FROM ubuntu:14.04

# Install security updates and required packages
RUN apt-get update && \
apt-get -y upgrade && \
apt-get -y install -q build-essential && \
apt-get -y install -q python-dev libffi-dev libssl-dev python-pip
RUN mkdir /app
ADD . /app

# Install requirements from the project's requirements.txt
RUN pip install -r /app/requirements.txt
WORKDIR /app
CMD ["python", "powerstrip-calico.py"]