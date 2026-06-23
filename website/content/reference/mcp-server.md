+++
title = "MCP server"
description = "The gnaw-mcp server: transport, the GNAW_MCP_ROOT confinement model, the extract and estimate tools, and what isn't exposed yet."
weight = 45
+++

`gnaw-mcp` is an [MCP](https://modelcontextprotocol.io) server that exposes
gnaw's extraction pipeline as tools. It is a thin adapter over the same
`run_extraction` the CLI uses, so a tool call produces the same output a CLI run
would for the equivalent config. This page is the contract; the
[how-to](/how-to/mcp-server/) covers installation and client setup.

## Transport

The server speaks JSON-RPC 2.0 over **stdio**. The MCP client launches the
`gnaw-mcp` process and communicates over its stdin/stdout; you do not start it
yourself. HTTP/SSE transport is not provided yet.

{% aside(kind="caution", title="stdout is the protocol channel") %}
Only JSON-RPC may be written to stdout — any other write corrupts the stream and
the client disconnects. `gnaw-mcp` routes all logging to stderr for this reason.
If you fork or extend it, keep stdout clean.
{% end %}

## Allowed root

The server confines all filesystem access to a single root directory, set by the
`GNAW_MCP_ROOT` environment variable (default: the process's working directory).
The value is canonicalized at startup. Every tool's `repo` argument is
canonicalized and must resolve **under** that root; anything that resolves
outside — including via `..` — is rejected with an invalid-parameters error.

This is the same confinement model as the [stdin path source](/reference/stdin-paths/):
canonicalize, then prove containment. A repo argument that doesn't exist on disk
is also rejected.

## Tools

### `extract`

Extracts a repository into an LLM-ready prompt.

| Argument | Type | Required | Description |
| --- | --- | --- | --- |
| `repo` | string | yes | Path to the repository. Must resolve under `GNAW_MCP_ROOT`. |
| `include` | string[] | no | Glob patterns to include (added to any `.gnawconfig` at the repo root). |
| `exclude` | string[] | no | Glob patterns to exclude. |

Returns the rendered prompt as text content. The run uses the working-tree
source and the repo's resolved configuration, identical to a plain `gnaw <repo>`
invocation.

### `estimate`

Takes the same arguments as `extract` and returns the token count and encoding
instead of the prompt body.

{% aside(kind="note", title="estimate is not cheaper yet") %}
`estimate` currently runs the same extraction as `extract` and discards the
body, so it does the same work — it's a quieter response, not a faster path. A
genuinely cheap estimate (counting without rendering) is a future change.
{% end %}

## Not exposed yet

The tool schemas deliberately omit several knobs because the pipeline does not
yet honor them, and advertising them would promise behavior that doesn't exist:

- **`budget`** — the pipeline runs unbudgeted (no token cap is enforced), so the
  tools count tokens but never trim to fit. Exposing a budget waits on budget
  enforcement landing in the pipeline.
- **`query` / relevance ranking** — ranking is uniform, so there's nothing for a
  query to steer. Exposing it waits on a real ranker.
- **Profiles** — gnaw has no named profile registry; configuration is per-repo
  via `.gnawconfig`. There is no `profiles` tool.

## See also

- [Use gnaw as an MCP server](/how-to/mcp-server/) — install, register, and drive
  it from chat.
- [Reading paths from stdin](/reference/stdin-paths/) — the same confinement
  pattern, applied to the CLI's piped-path source.
- [Output formats](/reference/output-formats/) — the structure of what `extract`
  returns.
