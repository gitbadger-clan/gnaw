+++
title = "Timing and performance"
description = "Use --timing to print how long a run took and a per-stage breakdown of where the time went."
weight = 45
+++

gnaw's `--timing` flag answers two questions at once: *how long did this run
take*, and *which stage spent the time*. It's the wall-clock companion to the
[token map](/reference/token-map/) — where the token map shows what's inflating
your context, `--timing` shows what's costing you seconds.

```sh
gnaw . --timing
```

All timing output goes to **stderr**, so it never contaminates the prompt on
stdout — you can pipe the prompt to a file or another process and still watch
the timing on your terminal.

## What you get

`--timing` does two things:

| Output | Measures |
| --- | --- |
| A `Took N.NNs` line | The whole CLI path — config load, directory walk, git, render, **and** the output write |
| A per-stage breakdown | Each pipeline stage, logged on the `gnaw::timing` target at debug level |

A run looks like this:

```text
source:          12.4ms  (218 items)
...
budget+count:    71.2ms  (193 chunks kept, 48210 tokens)
render:           6.7ms
TOTAL:          103.8ms
Took 0.12s
```

The two totals measure different spans, and the gap between them is itself
informative:

- **`TOTAL`** is the sum of the pipeline stages — pure construction
  (source, filter, chunk, rank, budget+count, render).
- **`Took`** is the entire user-perceived run: a superset that also includes
  spec construction, git-context loading, and writing the result to file or
  clipboard.

When `Took` is much larger than `TOTAL`, the time is in I/O — a large git diff,
a slow disk write — not in the pipeline itself.

## Just the breakdown, no flag

The per-stage lines are plain log records on a dedicated target, so you can
enable them through `RUST_LOG` without `--timing`:

```sh
RUST_LOG=gnaw::timing=debug gnaw .
```

That gives you the stage breakdown but **not** the `Took` one-liner, which is
tied to the flag. The two compose — set both and you get the breakdown plus the
total. `--timing` is really a convenience that flips this target on for you and
adds the wall-clock summary on top.

{% aside(kind="note", title="In the TUI") %}
`--timing` works with `gnaw --tui` as well, with one difference: there's no
`Took` line — a whole interactive session's wall time isn't a meaningful number.
The per-stage `gnaw::timing` breakdown is still enabled, so each prompt
generation inside the session logs the same stage lines.
{% end %}

{% aside(kind="tip", title="Pair it with the token map") %}
`--timing` and [`--token-map`](/reference/token-map/) answer adjacent questions —
seconds versus tokens. When a run feels heavy, reach for both: the token map
points at the files inflating the prompt, the timing breakdown points at the
stage spending the wall clock. They share no flags and combine freely.
{% end %}
