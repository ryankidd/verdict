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
    "message": "possible AWS access key"
  }
]
```

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
