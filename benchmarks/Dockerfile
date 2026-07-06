# Reproducible benchmark image for gnaw vs other context builders.
# Pinned: base image digest, tool versions, corpus commit. The image digest
# itself is the citable artifact — "benchmarked in sha256:..." is reproducible.
FROM debian:bookworm-slim


# GNU time (/usr/bin/time -v → peak RSS), hyperfine deps, git for corpus clone,
# curl for rustup, build essentials for compiling gnaw + cargo-installed tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
        time git curl ca-certificates build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# --- hyperfine (pinned) ---
ARG HYPERFINE_VERSION=1.20.0
RUN curl -L "https://github.com/sharkdp/hyperfine/releases/download/v${HYPERFINE_VERSION}/hyperfine_${HYPERFINE_VERSION}_amd64.deb" \
        -o /tmp/hyperfine.deb \
    && dpkg -i /tmp/hyperfine.deb && rm /tmp/hyperfine.deb

# --- Rust toolchain (pinned) ---
ARG RUST_VERSION=1.83.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# --- Node, ONLY if you have npx tools (pinned) ---
# ARG NODE_VERSION=22.x
# RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION} | bash - \
#     && apt-get install -y nodejs

# --- Competitor tools (pinned) ---
# FILL #1: one line per tool, pinned. Examples of the THREE shapes:
#   RUN cargo install --version 3.0.2 code2prompt        # crates.io
#   RUN cargo install --git https://github.com/x/yek --rev <sha> yek   # git
#   RUN npm i -g repomix@9.1.0                            # npm/npx
RUN echo "FILL: competitor tool install lines"

# --- gnaw (built from local source = the version under test) ---
# FILL #3: confirm build-from-source vs install-released.
WORKDIR /build
COPY . /build
RUN cargo build --release -p gnaw-ctx \
    && cp target/release/gnaw /usr/local/bin/gnaw
#
# can run `xtask bench-compare-inner` (the same measurement code as the host).
RUN cargo build --release -p gnaw-ctx -p xtask \
    && cp target/release/gnaw  /usr/local/bin/gnaw \
    && cp target/release/xtask /usr/local/bin/xtask
# --- Corpus (baked in at a pinned commit = immutable, native-FS reads) ---
# FILL #2: repo URL + SHA.
ARG CORPUS_REPO=https://github.com/vercel/next.js
ARG CORPUS_SHA=<FILL>
RUN git clone "${CORPUS_REPO}" /corpus \
    && cd /corpus && git checkout "${CORPUS_SHA}"

# Benchmark scripts live here; the actual run is invoked at `docker run` time
# (not baked into CMD) so you can pass --cpus/--memory and pick passes.
WORKDIR /corpus
