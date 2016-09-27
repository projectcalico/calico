# Ensure if you change this value, you also change the matching variable
# in the Dockerfile
CALICO_NODE_VERSION=v0.19.0

default: images
images: calico-node pull # redis
	  CALICO_NODE_VERSION=$(CALICO_NODE_VERSION) docker-compose -p mesoscni build

# Place tar of docker redis image into images/
# redis: images/redis.tar
# images/redis.tar:
# 	docker pull redis:alpine
# 	mkdir -p images
# 	docker save -o images/redis.tar redis:alpine

# Place tar of calico-node into images/
calico-node: images/calico-node-$(CALICO_NODE_VERSION).tar
images/calico-node-$(CALICO_NODE_VERSION).tar:
	docker pull calico/node:$(CALICO_NODE_VERSION)
	mkdir -p images
	docker save -o images/calico-node-$(CALICO_NODE_VERSION).tar calico/node:$(CALICO_NODE_VERSION)

pull:
	docker-compose -p mesoscni pull

clean:
	docker-compose -p mesoscni kill
	docker-compose -p mesoscni rm --force
	-rm -rf images/

cluster: images
	docker-compose -p mesoscni up -d
	docker-compose -p mesoscni scale agent=2

test-cni:
	docker exec mesoscni_mesosmaster_1 mesos-execute --containerizer=mesos --docker_image=busybox --name=cni --master=localhost:5050 --networks=calico-net-1 --command="ifconfig"
