This directory contains pre-requisite scripts and Dockerfile used to build a 
pyinstaller bundle for Felix.

The main entrypoint to build the bundle is the `build-pyi-bundle.sh` script
in the parent directory.

That script

- builds a Docker image with the build prerequisites baked in including 
  Python 2.7.11.
- runs pyinstaller in a container started with the built image.

The Dockerfile is based on the (reasonably old) Scientific Linux 6.5 in order
to ensure that all our dependencies are built against an older libc.  This 
ensures that the resulting pyinstaller-created binary will work on any newer
version.
