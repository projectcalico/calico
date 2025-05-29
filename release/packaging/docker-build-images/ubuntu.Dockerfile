# Set our build args (with defaults) 
ARG STREAM="noble"
ARG ARCH="amd64"

# We use our build args here to specify which image to start from
FROM --platform=linux/${ARCH} ubuntu:${STREAM}

# The `FROM` line 'consumes' the build args, so we have to bring them
# back into scope again for some reason
ARG STREAM
ARG ARCH

# We don't really need this but here we are
LABEL org.opencontainers.image.authors="Daniel Fox <dan.fox@tigera.io>"

# Run our command; we do some mount magic:
#    1. use cache mounts for apt directories, keyed on stream/arch
#    2. bind-mount the install deps script in so it doesn't live in the image
RUN \
    --mount=type=cache,sharing=locked,id=${STREAM}-${ARCH}-archives,target=/var/cache/apt/archives \
    --mount=type=cache,sharing=locked,id=${STREAM}-${ARCH}-lists,target=/var/lib/apt/lists \
    --mount=type=bind,source=install-ubuntu-build-deps,target=/install-ubuntu-build-deps \
    /install-ubuntu-build-deps

WORKDIR /code
