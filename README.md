<div align="center">
  <a href="https://gnaw.gitbadger.com">
    <img align="center" width="550px" src="website/static/assets/logo-wordmark-dark-ember.svg" alt="gnaw"/>
  </a>
  <br>
  <h3>Convert your codebase into a single LLM prompt.</h3>
  <p><sub>A Rust-native fork of <a href="https://github.com/mufeedvh/code2prompt">code2prompt</a>, extended with syntax-aware compression, a REST surface, and more.</sub></p>
</div>

<p align="center">
  <a href="https://gnaw.gitbadger.com"><b>Website</b></a> •
  <a href="https://gnaw.gitbadger.com/how-to/install/"><b>Documentation</b></a>
</p>

<div align="center">

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg?style=flat-square)](https://github.com/gitbadger-clan/gnaw#-license)
[![Tests](https://github.com/gitbadger-clan/gnaw/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/gitbadger-clan/gnaw/actions)
[![Crates.io Downloads](https://img.shields.io/crates/d/gnaw-ctx?style=flat-square&logo=rust)](https://crates.io/crates/gnaw-ctx)
[![GitHub Stars](https://img.shields.io/github/stars/gitbadger-clan/gnaw?style=social)](https://github.com/gitbadger-clan/gnaw)

</div>

<!-- Badges to add once published:
[![Crates.io](https://img.shields.io/crates/v/gnaw-ctx.svg?style=flat-square)](https://crates.io/crates/gnaw-ctx)
[![Docs.rs](https://docs.rs/gnaw-core/badge.svg?style=flat-square)](https://docs.rs/gnaw-core)
-->

---

<!-- TODO: add a demo gif at website/static/demo.gif and uncomment
<h1 align="center">
  <a href="https://gnaw.gitbadger.com"><img src="website/static/demo.gif" alt="gnaw demo"></a>
</h1>
-->

**gnaw** is a powerful context engineering tool designed to ingest codebases and format them for Large Language Models. Whether you are manually copying context for a chat assistant, building AI agents via Python, or wiring up a browser extension over REST, gnaw streamlines the context preparation process.

## ⚡ Quick Install

### Cargo

```bash
cargo install gnaw-ctx
```

The crates.io package is `gnaw-ctx`; the installed binary is `gnaw`.

To enable optional Wayland support (e.g., for clipboard integration on Wayland-based systems), use the `wayland` feature flag:

```bash
cargo install --features wayland gnaw-ctx
```

<!-- Homebrew — uncomment once a tap/formula is published:
### Homebrew

```bash
brew install gnaw
```
-->

### Python bindings 🐍

Built with PyO3/maturin. Not yet published to PyPI — build from source (see [Alternative Installation](#alternative-installation)).

## 🚀 Quick Start

Once installed, generating a prompt from your codebase is as simple as pointing the tool to your directory.

**Basic Usage**: Generate a prompt from the current directory and copy it to the clipboard.

```sh
gnaw .
```

**Save to file**:

```sh
gnaw path/to/project --output-file prompt.txt
```

### MCP server 🤖

Not yet on crates.io — build `gnaw-mcp` from source:

```bash
cargo install --git https://github.com/gitbadger-clan/gnaw gnaw-mcp
```

Then register it with your MCP client. See [Use gnaw as an MCP server](https://gnaw.gitbadger.com/how-to/mcp-server/).
## 🌐 Ecosystem

gnaw is more than just a CLI tool. It is a complete ecosystem for codebase context.

| 🧱 Core Library | 💻 CLI / TUI | 🐍 Python | 🌐 REST | 🤖 MCP |
| :---: | :---: | :---: | :---: | :---: |
| `gnaw-core` — the internal, high-speed library responsible for secure file traversal, respecting `.gitignore` rules, and structuring Git metadata. | Designed for humans, featuring both a minimal CLI and an interactive TUI. Generate formatted prompts, track token usage, and output the result to your clipboard or stdout. | Fast Python bindings to the Rust core. Ideal for AI agents, automation scripts, or deep integration into RAG pipelines. | A planned axum-based REST interface, enabling browser extensions and other clients to request well-structured context over HTTP. | An MCP server (gnaw-mcp) that lets agentic clients — Claude Code, Desktop, Cursor — call gnaw as a tool over stdio. See the [how-to.](https://gnaw.gitbadger.com/how-to/mcp-server/)|

## 📚 Documentation

Check our online [documentation](https://gnaw.gitbadger.com/how-to/install/) for detailed instructions.

## ✨ Features

gnaw transforms your entire codebase into a well-structured prompt for large language models. Key features include:

- **Terminal User Interface (TUI)**: Interactive terminal interface for configuring and generating prompts
- **Smart Filtering**: Include/exclude files using glob patterns and respect `.gitignore` rules
- **Flexible Templating**: Customize prompts with Handlebars templates for different use cases
- **Syntax-Aware Compression**: Chunk on whole functions and types via tree-sitter, not arbitrary line cuts
- **Token Tracking**: Track token usage to stay within LLM context limits
- **Git Integration**: Include diffs, logs, and branch comparisons in your prompts
- **Blazing Fast**: Built in Rust for high performance and low resource usage

Stop manually copying files and formatting code for LLMs. gnaw handles the tedious work so you can focus on getting insights and solutions from AI models.

## Alternative Installation

Refer to the [documentation](https://gnaw.gitbadger.com/how-to/install/) for detailed installation instructions.

### Binary releases

Download the latest binary for your OS from [Releases](https://github.com/gitbadger-clan/gnaw/releases).

### Source build

Requires [Git](https://git-scm.com/downloads), [Rust](https://www.rust-lang.org/tools/install) and `Cargo`.

```sh
git clone https://github.com/gitbadger-clan/gnaw.git
cd gnaw/
cargo install --path crates/gnaw
```

## ⭐ Star Gazing

[![Star History Chart](https://api.star-history.com/svg?repos=gitbadger-clan/gnaw&type=Date)](https://star-history.com/#gitbadger/gnaw&Date)

## 📊 Benchmarks

gnaw benchmarks itself against other repo-to-prompt tools ([repomix](https://github.com/yamadashy/repomix), [repomix-rs](https://github.com/sopaco/repomix-rs), [code2prompt](https://github.com/mufeedvh/code2prompt), [yek](https://github.com/mohsen1/yek)) on two axes, each with its own reproducible Docker image:

- **Throughput & peak memory on a real repo** — wall time (hyperfine), peak RSS, CPU utilization, and emitted file counts, with secret scanning on and off.
- **Memory scaling on generated corpora** — peak RSS plotted against corpus size (256 MB–8 GB of deterministic filler), to distinguish streaming from buffering behavior.

Both images pin every tool's version and normalize Rust build flags, so measured deltas reflect algorithms, not build configuration.

### Run the real-repo comparison

Requires Docker; the corpus repo is cloned at image build.

```sh
docker build -f benchmarks/Dockerfile -t gnaw-bench .
docker run --rm --cpus 8 --memory 8g \
  -v "$PWD:/out" \
  gnaw-bench \
  xtask bench-secret-inner --repo /corpus --out /out/bench.json
```

### Run the memory-scaling sweep

Corpus sizes are baked at image build via `CORPUS_SIZES_MB`; `bench-wrap` records OOM-killed runs as data points instead of losing them.

```sh
docker build -f benchmarks/Dockerfile.memscale -t gnaw-bench-mem .
for mb in 256 1024 2048 4096 8192; do
  docker run --rm --cpus 8 --memory 8g \
    -v "$PWD:/out" \
    gnaw-bench-mem \
    bench-wrap xtask bench-secret-inner --repo /corpus-${mb}m --out /out/secret_${mb}m.json
done
```

### Reading the numbers honestly

- Run on a **Linux host** for representative I/O, keep `--cpus`/`--memory` fixed across runs, and pin the corpus to a commit SHA when citing results.
- **File counts must match** (within ~1%) before timing comparisons mean anything — a tool that's faster on fewer files isn't faster.
- The generated corpus is a *memory* workload, not a speed workload — don't quote timing from the memscale image, and don't compare numbers across the two images.
- Node-based tools carry runtime startup in both time and RSS; the reports disclose this per-row.

Full methodology and results: [unicow.dev](https://unicow.dev/blog/context-compressor/).

## 🍴 Forked from code2prompt

gnaw began as a fork of [code2prompt](https://github.com/mufeedvh/code2prompt) by [Mufeed VH](https://github.com/mufeedvh) and contributors, and owes its foundation to that project. It carries forward the core idea — turning a codebase into a single, well-structured LLM prompt — while taking the tooling in a Rust-native direction and adding new capabilities:

- **Syntax-aware compression** — chunk on whole functions and types via tree-sitter, rather than arbitrary line cuts
- **REST interface** *(planned)* — an axum surface so browser extensions and other clients can request context over HTTP
- **MCP server** — exposes gnaw as a tool for agentic clients over MCP (stdio)

The original code2prompt is MIT licensed. gnaw is dual-licensed under MIT OR Apache-2.0; portions derived from code2prompt remain under the upstream MIT license, whose copyright notice is preserved. See [License](#-license) for details.

## 📜 License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/gitbadger-clan/gnaw/blob/main/LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/gitbadger-clan/gnaw/blob/main/LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Portions of this project are derived from [code2prompt](https://github.com/mufeedvh/code2prompt) and remain under its original MIT license; that copyright notice is retained in [LICENSE-MIT](https://github.com/gitbadger-clan/gnaw/blob/main/LICENSE-MIT).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Liked the project?

If you liked the project and found it useful, please give it a :star:!

## 👥 Contribution

Ways to contribute:

- Suggest a feature
- Report a bug
- Fix something and open a pull request
- Help document the code
- Spread the word
