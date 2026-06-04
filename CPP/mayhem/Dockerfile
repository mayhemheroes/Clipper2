FROM --platform=linux/amd64 ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    clang \
    cmake \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build the Clipper2 static library with ASan + no-link-fuzzer instrumentation
RUN cmake -S CPP -B /build \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address -g -O1" \
        -DCLIPPER2_EXAMPLES=OFF \
        -DCLIPPER2_TESTS=OFF \
        -DCLIPPER2_UTILS=OFF && \
    cmake --build /build --parallel $(nproc)

# Build the fuzzer binary linking against the static library
RUN clang++ -std=c++17 -fsanitize=fuzzer,address -g -O1 \
        -I CPP/Clipper2Lib/include \
        CPP/mayhem/fuzz_clipper.cpp \
        /build/libClipper2.a \
        -o /fuzz_clipper

FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /fuzz_clipper /fuzz_clipper
