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

## Output format

By default `verdict` prints the merged findings as a JSON array. Pass
`--format=markdown` for a human-readable report instead, grouped by tool and
then by file within each tool:

```sh
verdict --format=markdown secretscan.json lint.json
```

Each finding is listed with its location as `path:line`, its rule, its
severity, and its message:

```markdown
# Findings

## lint

### main.go

- main.go:3 — `unused` (warning): unused variable

## secretscan

### config.go

- config.go:12 — `aws-key` (error): possible AWS access key
```

Tools and the files under them are emitted in name order, and findings within
a file follow the same ordering as the JSON output, so the report is
deterministic. `--format=json` is the default and can be given explicitly.

The format only changes the rendering; `--fail-on` gating (below) applies the
same way in either format.

## Gating

`--fail-on=<severity>` turns a run into a check. After the merge is printed,
`verdict` exits non-zero if any finding's severity is at or above the given
level, and zero otherwise. Severities are ordered `error` > `warning` >
`info`, so `--fail-on=warning` trips on warnings and errors but not on info.

```sh
verdict --fail-on=error secretscan.json lint.json
```

The merge is always written to stdout, whether or not the threshold is met,
so the same command reports the findings and sets the status. This makes it a
drop-in CI step:

```sh
verdict --fail-on=error findings/*.json > merged.json
```

Findings whose severity is not one of `error`, `warning`, or `info` are
ignored for gating; they can't be placed in the ordering, so they never trip
the threshold.

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

| Code | Meaning                                                                    |
|------|----------------------------------------------------------------------------|
| `0`  | Success; no `--fail-on` threshold was met.                                 |
| `1`  | Usage or input error — a missing file, malformed input, or an invalid `--fail-on` value. |
| `2`  | A finding met the `--fail-on` threshold.                                   |

On a usage or input error `verdict` writes nothing to stdout; a partial merge
is never emitted. The threshold code (`2`) is kept distinct from the error
code (`1`) so CI can tell "the tool failed to run" apart from "the tool ran
and found something worth failing on".

## Development

```sh
go build ./...
go test ./...
```
