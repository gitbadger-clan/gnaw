+++
title = "Pipe content into gnaw"
description = "Send raw text or a file's bytes straight into gnaw on stdin — handy for scanning a key, an env file, or any ad-hoc content without writing it to disk first."
weight = 27
+++

gnaw usually walks a directory or takes a list of paths. But you can also pipe
**raw content** and gnaw will treat it as a single file named `stdin` — scanned,
counted, and rendered like any other. This is the quickest way to run a one-off
check on something you don't want to (or can't) save to disk first.

```sh
openssl genpkey -algorithm ed25519 | gnaw --secret-scan warn
```

That generates a private key, pipes it straight into gnaw, and the secret
scanner flags it — no temp file, no cleanup.

## When gnaw treats stdin as content

gnaw decides between a **path list** and **content** by looking at the input: if
any line names a file that exists under the root, it's a path list; otherwise
it's content. A key, an env file, or a log resolves to no files, so it's read as
content. gnaw prints which mode it chose:

```text
[i] stdin: treated as content
```

<!-- REVIEW: confirm the exact info-line wording against the binary. -->

If gnaw guesses wrong — content whose lines happen to name real files — force
content mode with `-`:

```sh
some-producer | gnaw -            # always content
```

See [Reading from stdin](/reference/stdin-paths/) for the exact rule.

## Scan a key or credential

The headline use is checking whether something is a secret before it lands
somewhere it shouldn't:

```sh
# A freshly generated key — the scanner should flag it
openssl genpkey -algorithm ed25519 | gnaw --secret-scan warn

# An env file you're about to share
cat .env | gnaw --secret-scan warn

# Refuse (non-zero exit) if anything looks like a secret — good in a script
printf '%s' "$SOME_VALUE" | gnaw --secret-scan block >/dev/null
```

In `block` mode the run exits non-zero when a finding turns up, so you can gate
on it:

```sh
if ! printf '%s' "$candidate" | gnaw --secret-scan block >/dev/null 2>&1; then
    echo "that looks like a secret — not committing it"
fi
```

## Turn arbitrary text into a prompt

Content mode isn't only for secrets — anything you pipe becomes a one-file
prompt, so the normal rendering flags apply:

```sh
# Wrap a snippet from the clipboard as a prompt (macOS)
pbpaste | gnaw -F xml

# Feed a command's output straight in
kubectl get pod mypod -o yaml | gnaw --secret-scan warn
```

The synthetic file is named `stdin` and carries no extension, so gnaw treats it
as plain text — syntax-aware compression and chunking don't apply. If you want
language-aware handling, write the content to a real file with the right
extension and point gnaw at it instead.

## What to know

- **Valid UTF-8 only.** Piping binary content (a DER-encoded key, an image)
  fails while reading stdin. Pipe text, or an armored/PEM form.
  <!-- REVIEW: confirm the failure message for binary input. -->
- **Whitespace-only input produces nothing** — an empty selection, not an empty
  `stdin` file.
- **Secret scanning is the same engine** as a normal run, so everything in
  [Scan for leaked secrets](/how-to/scan-for-secrets/) applies here too:
  policies, the redacted previews, and path allowlisting (though allowlisting by
  path is moot for a single synthetic file).

## See also

- [Reading from stdin](/reference/stdin-paths/) — the exact classification rule
  and the `-` / `--stdin-paths` force-modes.
- [Pipe a file list into gnaw](/how-to/pipe-file-list/) — the path-list side of
  stdin, for `git diff --name-only` and friends.
- [Scan for leaked secrets](/how-to/scan-for-secrets/) — the full secret-scanning
  walkthrough.
