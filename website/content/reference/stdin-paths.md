+++
title = "Reading paths from stdin"
description = "When gnaw reads a path list from stdin, how those paths are resolved, and how stdin mode interacts with filtering, templates, and the git flags."
weight = 35
+++

gnaw can take its file list from standard input instead of walking a directory:
pipe one repo-relative path per line and gnaw sources exactly those files. This
page is the precise contract; the [how-to](/how-to/pipe-file-list/) covers the
day-to-day workflows.

```sh
git diff --name-only | gnaw
```

## When stdin mode activates

gnaw reads stdin as a path list only when **all** of these hold:

| Condition | Why |
| --- | --- |
| stdin is not a terminal (it's piped or redirected) | A human at a prompt isn't sending a list |
| no path argument was given | An explicit path means "walk this"; it always wins |
| not in TUI mode (`--tui`) | The TUI drives its own selection |
| not the internal clipboard daemon | The daemon uses stdin for its own payload |

If any condition fails, gnaw behaves as before. In particular, a bare `gnaw` at
an interactive terminal prints help, and `gnaw .` (or any explicit path) walks
the tree even inside a pipeline.

{% aside(kind="note", title="The path argument still matters") %}
In stdin mode the path argument isn't discarded — it becomes the **root** that
piped relative paths resolve against. It defaults to `.`, which is why running
from the repository root makes `git`'s root-relative output line up. You don't
normally pass it, but a config-file `path` value still sets the root.
{% end %}

## How paths are resolved

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

## Ordering

The surviving files are **sorted by path**, not kept in the order they arrived
on stdin. This keeps output byte-stable for snapshot tests and matches the other
sources. If you need a specific order, it has to come from the rendered content,
not the pipe order.

## Interaction with other features

**Filtering is bypassed.** The piped list is treated as authoritative — you
named exactly these files — so `--include` / `--exclude` and `.gitignore` rules
do not apply to it. Binary/empty dropping and secret scanning still run.

**Secret scanning still applies.** The scrubber stage runs as normal, so
`--secret-scan=block` will still halt a stdin run that hits a finding, and
`redact` still masks.

**Stdin wins over the git source axes.** If a path list is present, it takes
precedence over `--git-diff-shas` and the git-narrative source selection. A run
is either "these piped files" or "this git range," not both.

**`--full-directory-tree` is ignored.** The source tree is always derived from
the piped files, so it lists exactly those paths and never expands to the whole
repository.

**Templates resolve normally.** Because a stdin run has no `--git-diff-shas`,
the default template (or your `--template`) is used. The git-narrative templates'
`{{git_diff}}` section stays empty unless you also pass `--diff`, which loads the
working-tree diff as chrome alongside the piped contents.

## See also

- [Pipe a file list into gnaw](/how-to/pipe-file-list/) — workflows and examples.
- [Git diffs and logs](/reference/git-context/) — folding diffs and logs into the
  prompt, and the per-file `--git-diff-shas` view.
- [Output formats](/reference/output-formats/) — `-F` and the rendered structure.
