+++
title = "Reading from stdin"
description = "How gnaw classifies piped stdin as either a path list or raw content, how paths are resolved, and how stdin mode interacts with filtering, templates, and the git flags."
weight = 35
+++

gnaw can take its input from standard input instead of walking a directory.
Piped stdin is read once and **classified** into one of two modes:

- **Path list** — one repo-relative path per line; gnaw sources exactly those
  files. This is the `git diff --name-only | gnaw` workflow.
- **Content** — the piped bytes are treated as a single synthetic file named
  `stdin`, scanned and rendered like any other file. This is the
  `openssl genpkey | gnaw --secret-scan warn` workflow.

This page is the precise contract; the how-to guides cover the day-to-day
workflows ([piping a file list](/how-to/pipe-file-list/),
[piping content](/how-to/pipe-content/)).

```sh
git diff --name-only | gnaw          # path list
cat config.env | gnaw --secret-scan warn   # content
```

## When stdin mode activates

gnaw reads stdin at all only when **all** of these hold:

| Condition | Why |
| --- | --- |
| stdin is not a terminal (it's piped or redirected) | A human at a prompt isn't sending input |
| no path argument was given | An explicit path means "walk this"; it always wins |
| not in TUI mode (`--tui`) | The TUI drives its own selection |
| not the internal clipboard daemon | The daemon uses stdin for its own payload |

If any condition fails, gnaw behaves as before. In particular, a bare `gnaw` at
an interactive terminal prints help, and `gnaw .` (or any explicit path) walks
the tree even inside a pipeline.

{% aside(kind="note", title="The path argument still matters") %}
In stdin mode the path argument isn't discarded — it becomes the **root** that
piped relative paths resolve against (and that content-vs-path classification
checks against). It defaults to `.`, which is why running from the repository
root makes `git`'s root-relative output line up. You don't normally pass it, but
a config-file `path` value still sets the root.
{% end %}

## How gnaw chooses path list vs content

Once gnaw has decided to read stdin, it classifies the input:

> **If any non-blank line resolves to an existing file under the root, the input
> is a path list. Otherwise it's content.**

The check is deliberately asymmetric. A real path list has lines that name real
files, so it takes only **one** resolving line to choose path mode — which means
every path-list workflow that worked before still works, including a
`git diff --name-only` where most listed files were deleted (those lines fail to
resolve, but any surviving file still tips the decision to path mode). Genuine
content — a PEM key, a log, a diff — resolves zero lines and falls through to
content mode.

gnaw prints the decision so a surprise is a one-glance diagnosis:

```text
[i] stdin: treated as path list
[i] stdin: treated as content
```

<!-- REVIEW: confirm the exact info-line wording against the binary before publishing. -->

The residual ambiguity is content whose lines *happen* to name real files (a
build log that mentions `src/main.rs`, say) — it classifies as a path list, most
lines drop, and you get a mostly-empty run. The info line above is how you catch
it; the force-modes below are how you fix it.

{% aside(kind="note", title="Classification depends on where you run gnaw") %}
Because resolution is against the root, the *same* piped input can classify
differently from different directories — a path list from the repo root may be
content from `/tmp`. This is inherent to any content sniff. The printed mode line
is the contract: trust it over the pipe.
{% end %}

## Forcing a mode

<!-- REVIEW: these force-modes were specified; confirm they shipped before publishing this section. If not yet built, cut it. -->

Two escape hatches override the sniff when you know better:

| Form | Forces |
| --- | --- |
| `gnaw -` (or `gnaw /dev/stdin`) | **content** — read stdin as one file, no classification |
| `gnaw --stdin-paths` | **path list** — treat every line as a path, even if none resolve |

`-` follows the Unix convention (`grep`, `cat`, `jq` all read stdin on `-`). A
bare `gnaw -` at an interactive terminal is an error, not a hang — pipe
something or pass a path.

## How paths are resolved (path-list mode)

Each non-blank line is trimmed, joined onto the root, and canonicalized:

- **Relative paths** resolve against the root (the path argument, default `.`).
- **Paths that resolve outside the root are dropped.** After canonicalization, a
  path that doesn't sit under the root is discarded — a piped `../../etc/passwd`
  can't escape the allowed root.
- **Paths that don't exist are dropped.** Deleted files (which still appear in
  `git diff --name-only`) fail to canonicalize and are skipped silently.
- **Binary and empty files are dropped** during extraction, identical to a
  normal walk.

Blank lines are ignored, so trailing newlines and empty input are harmless;
empty input yields an empty selection rather than an error.

## Content mode

When stdin is classified as content, gnaw builds a prompt from a single
synthetic file:

- The file is named **`stdin`** and carries **no extension**, so language-aware
  stages (syntax-aware compression, chunking) fall back to plain text — the only
  honest choice for bytes of unknown origin.
- **Secret scanning still runs.** `--secret-scan warn|redact|block` applies to
  the piped content exactly as it would to a file, which is what makes
  `openssl genpkey | gnaw --secret-scan warn` a useful check.
- **Whitespace-only input yields an empty selection**, not a one-line empty
  file — the same policy as an empty file in a walk.
- Input must be **valid UTF-8**. Piping binary (for example DER-encoded keys)
  fails while reading stdin rather than producing garbage.
  <!-- REVIEW: confirm the binary-input failure message; graceful handling was noted as a possible later improvement. -->

## Ordering (path-list mode)

The surviving files are **sorted by path**, not kept in the order they arrived
on stdin. This keeps output byte-stable for snapshot tests and matches the other
sources. If you need a specific order, it has to come from the rendered content,
not the pipe order.

## Interaction with other features

**Filtering is bypassed.** A piped path list is treated as authoritative — you
named exactly these files — so `--include` / `--exclude` and `.gitignore` rules
do not apply to it. Content mode has a single synthetic file, so filtering is
moot there too. Binary/empty dropping and secret scanning still run in both.

**Secret scanning still applies.** The scrubber stage runs as normal, so
`--secret-scan=block` will still halt a stdin run that hits a finding, and
`redact` still masks — in both path-list and content mode.

**Stdin wins over the git source axes.** If stdin supplied input, it takes
precedence over `--git-diff-shas` and the git-narrative source selection. A run
is either "this stdin input" or "this git range," not both.

**`--full-directory-tree` is ignored.** The source tree is always derived from
the stdin input, so it lists exactly the piped files (or the single `stdin`
file) and never expands to the whole repository.

**Templates resolve normally.** Because a stdin run has no `--git-diff-shas`,
the default template (or your `--template`) is used. The git-narrative templates'
`{{git_diff}}` section stays empty unless you also pass `--diff`, which loads the
working-tree diff as chrome alongside the piped input.

## See also

- [Pipe a file list into gnaw](/how-to/pipe-file-list/) — path-list workflows.
- [Pipe content into gnaw](/how-to/pipe-content/) — content-mode workflows.
- [Git diffs and logs](/reference/git-context/) — folding diffs and logs into the
  prompt, and the per-file `--git-diff-shas` view.
- [Output formats](/reference/output-formats/) — `-F` and the rendered structure.
