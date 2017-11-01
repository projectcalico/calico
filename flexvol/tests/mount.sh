#!/bin/bash

testDir="/tmp/t1"
input='{"kubernetes.io/fsGroup":"0","kubernetes.io/fsType":"","kubernetes.io/pod.name":"udsver-client-3419040874-jzd9n","kubernetes.io/pod.namespace":"default","kubernetes.io/pod.uid":"d113fb2d-bb61-11e7-bea2-080027631ab3","kubernetes.io/pvOrVolumeName":"test-volume","kubernetes.io/readwrite":"rw","kubernetes.io/serviceAccount.name":"default"}'

if [ $# -eq 1 ]; then	
	mkdir -p ${testDir}
	chmod 777 ${testDir}
	$1 mount ${testDir} ${input}
else
	umount ${testDir}
fi
