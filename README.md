# verdict

A small command-line tool for working with scan findings — the output of
linters, security scanners, and similar tools — in a single, uniform JSON
shape.

`verdict` reads JSON arrays of findings, merges them into one deduplicated
set, and prints it to stdout in a deterministic order.

```json
[
  {
    "tool": "secretscan",
    "rule": "aws-key",
    "severity": "error",
    "path": "config.go",
    "line": 12,
    "message": "possible AWS access key",
    "fingerprint": "e9bd80b48541ce73"
  }
]
```

## The finding envelope

This shape is a stable contract, defined in
[`schema/finding.schema.json`](schema/finding.schema.json). Any tool that
wants its output aggregated by verdict should emit an array of objects
matching it.

| Field         | Required | Meaning                                                          |
|---------------|----------|-------------------------------------------------------------------|
| `tool`        | yes      | Name of the tool that produced the finding, e.g. `secretscan`.    |
| `rule`        | yes      | Tool-specific rule or check identifier, e.g. `aws-key`.           |
| `severity`    | yes      | One of `error`, `warning`, `info`.                                |
| `path`        | yes      | File path the finding applies to, relative to the scan root.      |
| `line`        | yes      | 1-indexed line number.                                            |
| `message`     | yes      | Human-readable description.                                       |
| `fingerprint` | no       | Stable identifier for the finding, for deduping across runs.      |

`fingerprint` is a SHA-256 digest (truncated to 16 hex characters) of
`tool`, `rule`, `path`, and `line`, joined by NUL bytes. `message` is
deliberately excluded from the derivation, so rewording a message doesn't
change the fingerprint and doesn't churn dedupe state downstream.

A tool may supply its own `fingerprint`, which is used as-is. If omitted,
`verdict` computes and fills one in when decoding.

## Install

```sh
go install github.com/ryankidd/verdict@latest
```

## Usage

Pass one or more findings files, or pipe a single one in on stdin:

```sh
verdict secretscan.json lint.json audit.json
cat findings.json | verdict
```

Either way the output is a single JSON array containing the merged findings.

## Merging

Findings from every input file go into one set, in the order the files were
given.

**Deduplication.** Two findings are duplicates when they share a
`fingerprint`; only the first occurrence is kept, scanning the files left to
right and each file top to bottom. Because the fingerprint is derived from
`tool`, `rule`, `path`, and `line`, duplicates may still disagree on
`severity` and `message` — the same issue reported twice, worded differently
or graded differently. The fingerprint is the identity of the finding, so the
later copy is dropped whole rather than merged field by field, and the earlier
input wins. Order the arguments accordingly if one source is more
authoritative than another.

**Ordering.** The merged set is sorted by `path`, then `line`, then `rule`,
then `tool`, then `fingerprint`. That key is total across findings that
survive deduplication, so the output does not depend on the order the files
were given. `fingerprint` is part of the key only to break ties between
findings that carry tool-supplied fingerprints, which can otherwise agree on
all four preceding fields.

Given inputs whose duplicates agree on the fields outside the fingerprint,
runs are byte-identical regardless of argument order — which makes the output
safe to commit, diff, or compare between builds.

## Exit status

`verdict` exits non-zero and writes nothing to stdout if any input file is
missing or does not contain a valid array of findings. A partial merge is
never emitted.

## Development

```sh
go build ./...
go test ./...
```
