# Reproducible benchmark image for gnaw vs other context builders.
# Multi-stage: heavy toolchain + compile live in the builder and never ship.
# The final image carries only runtime deps, the built binaries, the npm tools
# (which need Node), and the baked corpus. The image digest is the citable
# artifact — "benchmarked in sha256:..." is reproducible.

# =============================================================================
# STAGE 1 — builder: Rust toolchain, cargo-installed competitors, gnaw+xtask.
# Everything here (toolchain, target/, cargo caches) stays in this stage.
# =============================================================================
FROM debian:bookworm-slim AS builder

# Build deps: zlib1g-dev added (libz-sys/git2 need zlib.h to compile).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates build-essential pkg-config libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Rust toolchain (pinned). PATH set BEFORE the RUN so rustup is findable. ---
ARG RUST_VERSION=1.90.0
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain none \
    && rustup toolchain install ${RUST_VERSION} \
    && rustup default ${RUST_VERSION}

# Normalize release build flags across ALL Rust tools (gnaw + competitors) so
# measured deltas reflect algorithms, not build config. Anchored to gnaw's
# shipping profile. panic is deliberately NOT normalized: forcing abort onto
# crates that may rely on unwinding is risky, and its throughput effect is noise.
ENV CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

# --- Rust competitors (pinned), into ~/.cargo/bin. Cache cleaned same layer. ---
RUN cargo install --version 4.3.0 code2prompt \
    && cargo install --git https://github.com/mohsen1/yek --rev v0.25.5 yek \
    && rm -rf /root/.cargo/git /root/.cargo/registry

RUN cargo install --git https://github.com/sopaco/repomix-rs \
        --rev 5798dc0ffb79b3b99b3781040f844d56e9bb36ef \
        --root /opt/bench-tools/repomix-rs-src \
        repomix-cli \
    && rm -rf /root/.cargo/git /root/.cargo/registry

# --- gnaw + xtask (built from local source = the versions under test) ---
WORKDIR /build
COPY . /build
RUN cargo build --release -p gnaw-ctx -p xtask

# =============================================================================
# STAGE 2 — final: slim runtime. Only what's needed to RUN the benchmark.
# =============================================================================
FROM debian:bookworm-slim

ENV BENCH_TOOLS_DIR=/opt/bench-tools
# Runtime deps (NOT -dev): GNU time for peak RSS, git for corpus clone at build,
# curl for hyperfine, ca-certs, and the RUNTIME shared libs the Rust binaries
# link (libssl3, zlib1g — the .so's, not the headers). If a binary fails at
# launch with "cannot open shared object", add the missing runtime lib here.
RUN apt-get update && apt-get install -y --no-install-recommends \
        time git curl ca-certificates libssl3 zlib1g \
    && rm -rf /var/lib/apt/lists/*

# --- hyperfine (pinned, arch-aware via TARGETARCH) ---
ARG HYPERFINE_VERSION=1.20.0
ARG TARGETARCH
RUN curl -L "https://github.com/sharkdp/hyperfine/releases/download/v${HYPERFINE_VERSION}/hyperfine_${HYPERFINE_VERSION}_${TARGETARCH}.deb" \
        -o /tmp/hyperfine.deb \
    && dpkg -i /tmp/hyperfine.deb && rm /tmp/hyperfine.deb

# --- Node (required for repomix / repomix-rs, which are npm-distributed) ---
ARG NODE_VERSION=26.x
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION} | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- Binaries from the builder: gnaw, xtask, and the cargo competitors. ---
# These are self-contained executables — safe to lift into the slim stage.
COPY --from=builder /build/target/release/gnaw   /usr/local/bin/gnaw
COPY --from=builder /build/target/release/xtask  /usr/local/bin/xtask
COPY --from=builder /root/.cargo/bin/code2prompt /usr/local/bin/code2prompt
COPY --from=builder /root/.cargo/bin/yek         /usr/local/bin/yek
COPY --from=builder /opt/bench-tools/repomix-rs-src/bin/repomix /usr/local/bin/repomix-rs

# --- npm competitors (pinned). MUST be in the final stage: they're
# node_modules trees that need Node to run, not liftable binaries. Separate
# prefixes — both packages ship a `repomix` binary and would collide in a
# shared node_modules. resolve_exec finds them via each prefix's .bin shim.
RUN npm install --prefix /opt/bench-tools/node/repomix     repomix@1.16.0

# --- Corpus (shallow-ish, pinned, history dropped for size) ---
ARG CORPUS_REPO=https://github.com/vercel/next.js
ARG CORPUS_SHA=70e3934fc6acc4b56a764c4060fee4b55f849aa3
RUN git clone "${CORPUS_REPO}" /corpus \
    && cd /corpus && git checkout "${CORPUS_SHA}" && rm -rf .git

# The run is invoked at `docker run` time (not baked into CMD) so you can pass
# --cpus/--memory and pick passes. Corpus is the workdir.
WORKDIR /corpus
