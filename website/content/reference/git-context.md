+++
title = "Git diffs and logs"
description = "Inject working-tree diffs, branch diffs, branch logs, and per-file changed content into the prompt with gnaw's git flags."
weight = 30
+++

gnaw can fold live git context into the output so a model sees what you're
working on now and how the code has moved, not just a static snapshot. There are
several independent sources, each surfaced as its own section in the rendered
prompt.

## Working-tree diff

`-d` / `--diff` injects the current diff. `--diff-mode` chooses which changes,
and **requires `--diff`** to be set.

| `--diff-mode` | Diff shown |
| --- | --- |
| `staged` *(default)* | Staged changes only |
| `unstaged` | Unstaged working-tree changes |
| `all` | All uncommitted changes |

```sh
gnaw . --diff                      # staged (default)
gnaw . --diff --diff-mode unstaged
gnaw . --diff --diff-mode all
```

This populates the `git_diff` template variable, rendered under a `<git-diff>`
tag (XML) or a `Git Diff:` heading (Markdown).

## Diff between two branches

`--git-diff-branch` takes **two** refs (comma- or space-separated) and renders the
diff between them:

```sh
gnaw . --git-diff-branch main,feature/login
gnaw . --git-diff-branch v1.0.0 HEAD
```

This populates `git_diff_branch`.

## Log between two branches

`--git-log-branch` likewise takes two refs and injects the commit log across that
range:

```sh
gnaw . --git-log-branch main,feature/login
```

This populates `git_log_branch`.

{% aside(kind="note", title="Three separate variables") %}
`git_diff`, `git_diff_branch`, and `git_log_branch` are distinct and can all
appear in one run. A custom template can reference each independently with
`{{#if git_diff}}…{{/if}}` and the matching names — handy if you want, say, the
branch log but not the working-tree diff.
{% end %}

{% aside(kind="tip", title="Pairs well with the commit-splitting template") %}
The built-in template for proposing an atomic commit sequence expects a diff —
run it with `--diff --diff-mode unstaged` (or `all`) so there's a changeset to
work from.
{% end %}

## Per-file changed content between two refs

The diff sources above hand the model one unified patch. `--git-diff-shas`
instead emits a **per-file view** of everything that changed between two refs:
each changed file gets its own section with the chosen content, and the source
tree is scoped to just those files rather than the whole repo. It's the right
shape when you want the model to reason file-by-file about a range of commits.

`--git-diff-shas` accepts the two refs as `ref1..ref2`, `ref1,ref2`, or two
space-separated tokens:

```sh
gnaw . --git-diff-shas main..feature/login
gnaw . --git-diff-shas v1.0.0,HEAD
gnaw . --git-diff-shas HEAD~3 HEAD
```

Renamed files are detected and labelled; binary files are reported as changed
rather than silently dropped.

### Choosing what each file shows

`--git-diff-shas-content` picks how much per-file content to emit. It **requires
`--git-diff-shas`**.

| Value | Per file |
| --- | --- |
| `patch` | The unified patch only (plus the full body for added files). Leanest, ~1× the changed content. |
| `after-patch` *(default)* | The full *after* body of every changed file, plus the patch. No *before*. |
| `full` | Full *before* and *after* bodies, no patch. ~2×. |
| `full-patch` | Full *before* and *after* plus the patch. Heaviest. |

```sh
gnaw . --git-diff-shas main..HEAD --git-diff-shas-content patch
gnaw . --git-diff-shas main..HEAD --git-diff-shas-content full-patch
```

### Capping large files

`--git-diff-shas-max-bytes` skips per-file content above the given byte size
(`0`, the default, means no limit). Oversized files are reported as changed with
their content left out. It also **requires `--git-diff-shas`**.

```sh
gnaw . --git-diff-shas main..HEAD --git-diff-shas-max-bytes 200000
```

## Changed-files tree for git-narrative templates

The git-narrative built-in templates — `write-git-commit`,
`write-git-changeset-commits`, and `write-github-pull-request` — only need to
see *which* files the change touches, not the whole repository. When one of
these is in effect (selected automatically by the git flags, or chosen
explicitly with `--template`), gnaw scopes the rendered source tree to the
changed files. The diff and log still render as their own sections; the tree
just stops listing files that weren't part of the change.

- A commit / changeset run (with `--diff`) scopes the tree to the working-tree
  changes for the active `--diff-mode`.
- A pull-request run (with `--git-diff-branch` or `--git-log-branch`) scopes the
  tree to the files changed between the two refs.

A git-narrative template invoked without any git context (for example a bare
`--template write-git-commit`) has nothing to scope to, so it falls back to the
whole-repository tree.
