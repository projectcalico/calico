FROM ubuntu:18.04
RUN apt-get update && apt-get install -y sudo build-essential wget git \
&& apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common \
&& curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o output.txt && sudo apt-key add "output.txt" \
&&  sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
&&  sudo apt-get install docker-ce-cli