# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang cmake

## Add source code to the build stage.
ADD ./CPP /Clipper2
WORKDIR /Clipper2

## Build
RUN cmake -DCLIPPER2_TESTS=0 -DCLIPPER2_EXAMPLES=0 -DMAYHEM=1
RUN make -j$(nproc)

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /Clipper2/mayhem/fuzz_clipper /fuzz_clipper
ex
## Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_clipper
