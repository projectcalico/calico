#!/bin/bash
k8s_ver="v1.7.0"

download_path="k8s"
binaries="kubectl kube-apiserver kube-controller-manager kubelet kube-proxy kube-scheduler"
install_binaries="false"

while [[ $# -gt 0 ]]; do
	key="$1"
	case $key in
		--dl-dir)
			download_path="$2"
			shift
			;;
		--install)
			install_binaries="true"
			;;
		--binaries)
			shift
			binaries="$@"
			break
			;;
	esac
	shift
done

if [ ! -d $download_path ]; then
  mkdir -p $download_path
fi

for x in $binaries; do
  ver_binary=${x}-$k8s_ver
  if [ ! -f $download_path/${ver_binary}.downloaded ]; then
    /usr/bin/wget -O $download_path/${ver_binary} https://storage.googleapis.com/kubernetes-release/release/$k8s_ver/bin/linux/amd64/$x
    if [ $? -eq 0 ]; then
      touch $download_path/${ver_binary}.downloaded
    fi
  else
    echo "$x ($k8s_ver) already downloaded"
  fi
done

if [ "$install_binaries" == "true" ]; then
  echo "Installing binaries"
  mkdir -p /opt/bin

  for x in $binaries; do
    binary=$x
    ver_binary=${binary}-$k8s_ver
    if [ ! -f $download_path/${ver_binary}.downloaded ]; then
      echo "ERROR: $binary version $k8s_ver was not downloaded"
      exit 1
    fi
    cp $download_path/${ver_binary} /opt/bin/$binary
    /usr/bin/chmod +x /opt/bin/$binary
  done
fi
