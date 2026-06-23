+++
title = "Use gnaw as an MCP server"
description = "Run gnaw's MCP server so Claude Code, Claude Desktop, Cursor, or any MCP client can call codebase extraction as a tool during a session."
weight = 30
+++

gnaw ships an [MCP](https://modelcontextprotocol.io) server, `gnaw-mcp`, that
exposes extraction as tools an AI assistant can call mid-conversation. It's a
thin adapter over the same pipeline the CLI runs, talking JSON-RPC over stdio —
the client launches the binary and drives it.

## Install the binary

`gnaw-mcp` isn't on crates.io yet, so build it from source:

```sh
# From a checkout of the repo
cargo install --path crates/gnaw-mcp

# Or without cloning
cargo install --git https://github.com/gitbadger-clan/gnaw gnaw-mcp
```

Either puts `gnaw-mcp` on your `PATH`. Note its location with `which gnaw-mcp` —
you'll need the absolute path to register it.

{% aside(kind="note", title="Source build for now") %}
Prebuilt release binaries and a crates.io publish are planned. Until then, the
source build above is the supported path.
{% end %}

## Choose an allowed root

`gnaw-mcp` confines every request to a single root directory, set with the
`GNAW_MCP_ROOT` environment variable (default: the server's working directory).
A tool call asking for a repo outside that root is rejected. Set it to a
**parent** of the projects you want reachable — not a single project — so the
assistant can extract any repo beneath it:

```sh
GNAW_MCP_ROOT=/Users/you/projects
```

## Register with a client

**Claude Code** — one command, picked up next session:

```sh
claude mcp add gnaw \
  --env GNAW_MCP_ROOT=/Users/you/projects \
  -- /abs/path/to/gnaw-mcp
```

Then `/mcp` in a session lists `gnaw` with its tools.

**Claude Desktop** — edit `claude_desktop_config.json` and **fully restart** the
app (a window close isn't enough; it reads config only on launch):

```json
{
  "mcpServers": {
    "gnaw": {
      "command": "/abs/path/to/gnaw-mcp",
      "env": { "GNAW_MCP_ROOT": "/Users/you/projects" }
    }
  }
}
```

**Cursor** uses the same shape in `.cursor/mcp.json` (project) or
`~/.cursor/mcp.json` (global).

{% aside(kind="caution", title="Use an absolute binary path") %}
The client spawns `gnaw-mcp` from its own working directory, not yours, so a
relative path won't be found. `which gnaw-mcp` gives you the absolute path to
paste.
{% end %}

## Drive it from chat

Once connected, ask the assistant to use the tools by name the first few times,
since it picks them from their descriptions:

- *"Use the gnaw `estimate` tool on /Users/you/projects/myrepo."*
- *"Run gnaw `extract` on that repo and summarize the architecture."*

The client shows an approval prompt on first use; approve it and the tool call,
its arguments, and the result appear inline.

{% aside(kind="tip", title="Start with estimate") %}
`extract` returns the entire rendered prompt, which dumps a whole codebase into
the conversation — exactly what you want in production, but noisy while you're
checking the wiring. `estimate` returns a single token count, so it confirms the
pipeline ran end to end without flooding the chat. Graduate to `extract` once
estimate works.
{% end %}

## Verify without a client

The MCP Inspector exercises the server directly — good for a first smoke test or
CI:

```sh
# List the exposed tools and their schemas
npx @modelcontextprotocol/inspector --cli ./target/release/gnaw-mcp --method tools/list

# Call extract on a repo under your root
npx @modelcontextprotocol/inspector --cli \
  -e GNAW_MCP_ROOT=/Users/you/projects -- ./target/release/gnaw-mcp \
  --method tools/call --tool-name extract --tool-arg repo=/Users/you/projects/myrepo
```

## Gotchas

- **`GNAW_MCP_ROOT` must contain your target repos.** A request to a repo outside
  it returns "escapes the allowed root" — which looks broken but is the
  confinement working. Point the root at a parent directory.
- **Pass absolute `repo` paths.** A relative path resolves against the server's
  working directory, which is unpredictable for a client-spawned process.
- **Rebuild and restart after code changes.** The client holds the spawned
  process for the session, so a fresh `cargo build` doesn't reach a running
  client until you restart it (Desktop) or start a new session (Code).

## See also

- [MCP server reference](/reference/mcp-server/) — the exact tools, arguments,
  confinement rules, and what isn't exposed yet.
- [Pipe a file list into gnaw](/how-to/pipe-file-list/) — the non-MCP way to feed
  a specific set of files to a chat surface.
