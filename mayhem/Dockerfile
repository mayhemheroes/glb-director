FROM debian:bullseye AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    libjansson-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . /repo
RUN clang++ /repo/mayhem/fuzz_glb_log_info.cpp \
    -fsanitize=fuzzer,address \
    -I /repo/src/glb-director \
    -ljansson \
    -o /fuzz

FROM debian:bullseye AS package
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libjansson4 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /fuzz /fuzz_glb_log_info
