# Provenance

Vendored from <https://github.com/hzrd149/blossom> (public domain) so that
implementation lanes and reviewers work from a stable, offline copy of the
protocol instead of a moving branch.

- `00.md` .. `12.md` are the BUDs, unmodified.
- `SPEC-README.md` is the upstream repository README.
- `implementations/` holds upstream implementation notes, unmodified.

Refresh with:

```sh
git clone --depth 1 https://github.com/hzrd149/blossom /tmp/blossom-spec
cp /tmp/blossom-spec/buds/*.md docs/buds/
```
