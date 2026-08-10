# verdict

A small command-line tool for working with scan findings — the output of
linters, security scanners, and similar tools — in a single, uniform JSON
shape.

`verdict` reads a JSON array of findings from stdin and pretty-prints it to
stdout.

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

```sh
cat findings.json | verdict
```

## Development

```sh
go build ./...
go test ./...
```
