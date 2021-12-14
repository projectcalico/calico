#!/bin/bash

PHASES=(${@:-SETUP RUN RUN_ASAN CLEANUP})
DEBIAN_RELEASE="${DEBIAN_RELEASE:-testing}"
CONT_NAME="${CONT_NAME:-libbpf-debian-$DEBIAN_RELEASE}"
ENV_VARS="${ENV_VARS:-}"
DOCKER_RUN="${DOCKER_RUN:-docker run}"
REPO_ROOT="${REPO_ROOT:-$PWD}"
ADDITIONAL_DEPS=(clang pkg-config gcc-10)
CFLAGS="-g -O2 -Werror -Wall"

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

function error() {
    echo -e "\033[31;1m$1\033[0m"
}

function docker_exec() {
    docker exec $ENV_VARS -it $CONT_NAME "$@"
}

set -eu

source "$(dirname $0)/travis_wait.bash"

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            info "Using Debian $DEBIAN_RELEASE"

            docker --version

            docker pull debian:$DEBIAN_RELEASE
            info "Starting container $CONT_NAME"
            $DOCKER_RUN -v $REPO_ROOT:/build:rw \
                        -w /build --privileged=true --name $CONT_NAME \
                        -dit --net=host debian:$DEBIAN_RELEASE /bin/bash
            docker_exec bash -c "echo deb-src http://deb.debian.org/debian $DEBIAN_RELEASE main >>/etc/apt/sources.list"
            docker_exec apt-get -y update
            docker_exec apt-get -y install aptitude
            docker_exec aptitude -y build-dep libelf-dev
            docker_exec aptitude -y install libelf-dev
            docker_exec aptitude -y install "${ADDITIONAL_DEPS[@]}"
            ;;
        RUN|RUN_CLANG|RUN_GCC10|RUN_ASAN|RUN_CLANG_ASAN|RUN_GCC10_ASAN)
            if [[ "$phase" = *"CLANG"* ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
                CC="clang"
            elif [[ "$phase" = *"GCC10"* ]]; then
                ENV_VARS="-e CC=gcc-10 -e CXX=g++-10"
                CC="gcc-10"
            else
                CFLAGS="${CFLAGS} -Wno-stringop-truncation"
            fi
            if [[ "$phase" = *"ASAN"* ]]; then
                CFLAGS="${CFLAGS} -fsanitize=address,undefined"
            fi
            docker_exec mkdir build install
            docker_exec ${CC:-cc} --version
            info "build"
	    docker_exec make -j$((4*$(nproc))) CFLAGS="${CFLAGS}" -C ./src -B OBJDIR=../build
            info "ldd build/libbpf.so:"
            docker_exec ldd build/libbpf.so
            if ! docker_exec ldd build/libbpf.so | grep -q libelf; then
                error "No reference to libelf.so in libbpf.so!"
                exit 1
            fi
            info "install"
            docker_exec make -j$((4*$(nproc))) -C src OBJDIR=../build DESTDIR=../install install
            docker_exec rm -rf build install
            ;;
        CLEANUP)
            info "Cleanup phase"
            docker stop $CONT_NAME
            docker rm -f $CONT_NAME
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
