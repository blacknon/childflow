# Contributing

Thanks for helping improve `childflow`.

## Before You Open A PR

- Open an issue first for large behavior changes or feature ideas.
- Keep pull requests focused on one change.
- Update docs or examples when user-facing behavior changes.
- Add or update tests when behavior changes.

## Development Notes

- `childflow` targets Linux.
- Prefer small, reviewable patches over broad refactors.
- Keep the default `rootless-internal` path stable unless the change explicitly targets another backend.

## Validation

Run the closest relevant checks before sending a pull request.

```bash
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

If your change affects demos, profiles, or networking behavior, include the exact commands you used to validate it.

## Pull Request Tips

- Explain the user problem, not just the code change.
- Include command examples, flow-log snippets, or screenshots when they help reviewers.
- Call out breaking changes, Linux capability requirements, or backend-specific behavior clearly.
