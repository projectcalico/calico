FROM alpine:3

# Put our binary in /code rather than directly in /usr/bin.  This allows the downstream builds
# to more easily extract the apiserver build artifacts from the container.
RUN mkdir /code
RUN chgrp -R 0 /code && \
    chmod -R g=u /code
ADD bin/apiserver /code
WORKDIR /code
RUN ln -s /code/apiserver /usr/bin

# Run apiserver by default
ENTRYPOINT ["apiserver"]
