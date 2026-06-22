+++
title = "Pipe a file list into gnaw"
description = "Feed gnaw a newline-delimited list of paths on stdin — from git, fd, or ripgrep — to build a prompt from exactly those files, no walk and no globbing."
weight = 25
+++

gnaw reads a list of file paths from standard input and builds a prompt from
**exactly those files** — no directory walk, no glob matching. The canonical use
is handing it the output of `git`, so a model sees precisely what you changed:

```sh
git diff --name-only | gnaw
```

That pipes the names of your unstaged changes into gnaw, which sources each one,
counts tokens, and renders the prompt to stdout like any other run.

{% aside(kind="caution", title="Don't pass a path") %}
Stdin mode fires only when input is piped **and** you give no path argument.
`git diff --name-only | gnaw .` disables it — the explicit `.` means "walk the
current directory" and the pipe is ignored. Leave the path off to let the pipe
take over. See [Reading paths from stdin](/reference/stdin-paths/) for the exact
rule.
{% end %}

## Common git workflows

All of these run from the **repository root**, because `git` prints paths
relative to the root and gnaw resolves them against your current directory.

```sh
# Unstaged working-tree changes
git diff --name-only | gnaw

# Staged changes only
git diff --cached --name-only | gnaw

# Everything changed since three commits back
git diff --name-only HEAD~3 | gnaw

# Changes on this branch versus main
git diff --name-only main...HEAD | gnaw
```

## Other producers

Anything that emits one path per line works. A few that pair well:

```sh
# Every Rust file under src/ (fd)
fd -e rs . src | gnaw

# Files that mention a symbol (ripgrep -l lists matching files)
rg -l TODO | gnaw

# A hand-curated list kept in a file
cat review-set.txt | gnaw
```

## Shaping the output

The piped list only decides *which files*. Everything else — format, template,
destination — composes exactly as in a normal run:

```sh
# Write straight to a file
git diff --name-only | gnaw -O context.md

# Copy to the clipboard (macOS)
git diff --name-only | gnaw | pbcopy

# JSON, then inspect which files landed
git diff --name-only | gnaw -F json | jq '.files[].path'
```

A custom or built-in content template applies as usual with `-t` / `--template`:

```sh
git diff --name-only | gnaw -t refactor
```

{% aside(kind="tip", title="For change review, add --diff") %}
The git-narrative templates (`write-git-commit`, `write-github-pull-request`)
render a `{{git_diff}}` section that a plain stdin run leaves empty — stdin
supplies file *contents*, not a diff. To get both the changed files and the
actual diff, pair the pipe with `--diff` so the diff chrome is loaded:

```sh
git diff --name-only | gnaw -t write-git-commit --diff
```

`--diff` reads the working-tree diff independently, so make sure it describes the
same change set you piped. For per-file change views without piping, see
[Git diffs and logs](/reference/git-context/).
{% end %}

## What gets dropped

gnaw quietly skips paths it can't use, so a messy list is safe to pipe:

- **Deleted files** — they appear in `git diff --name-only` but no longer exist
  on disk, so they can't be read.
- **Binary and empty files** — dropped during extraction, same as a normal walk.
- **Paths outside the root** — anything that resolves above your current
  directory is confined out, so a stray `../secrets` can't escape.

## Gotchas

{% aside(kind="caution", title="Use --name-only, run from the root") %}
- Use `git diff --name-only`, not `--name-status` (the status column would be
  read as part of the path) or a bare `git diff` (patch hunks aren't paths).
- Don't use `-z` / NUL-delimited output — gnaw splits the list on newlines only.
- Run from the repository root so git's root-relative paths line up with gnaw's
  resolution against the current directory.
{% end %}

## Next steps

The [Reading paths from stdin](/reference/stdin-paths/) reference spells out the
trigger conditions, path resolution, and how stdin interacts with filtering and
templates. For folding git history into the prompt instead of just the file
list, see [Git diffs and logs](/reference/git-context/).
