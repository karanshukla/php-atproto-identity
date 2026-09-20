# Branch rulesets

The same protection kodamachi-feed runs, as API payloads. Apply both with:

```bash
for f in .github/rulesets/*.json; do
  gh api repos/karanshukla/php-atproto-identity/rulesets -X POST --input "$f"
done
```

`protect-main.json` requires three status checks by name: `PHP 8.4`, `PHP 8.5`
and `No gmp or bcmath`. Those are the rendered `name:` fields of the jobs in
`../workflows/ci.yml`, not the job ids — and the first two come from the
matrix, so changing the PHP versions there means updating this file too.

There is no CodeQL entry: CodeQL has no PHP analyzer. `composer audit` in the
`PHP 8.4` and `PHP 8.5` jobs is the security gate instead.
