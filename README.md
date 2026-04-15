# pindrop

Minimal Go library scaffold for security scanning and code quality analysis.

## Quick start

```bash
go test ./...
```

## Project layout

- `pkg/analyzer`: shared types and small starter logic for analyzers.

## Next steps

- Add concrete analyzers under `pkg/analyzer` or feature-specific packages.
- Extend `Finding` and `Result` types with metadata you need.
- Add input adapters for files, repositories, or CI pipelines.
