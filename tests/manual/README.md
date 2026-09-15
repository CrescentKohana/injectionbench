# Manual test cases

These cases cannot be automated against the specified interface. Each lists the
precondition, steps, expected result, and why automation is out of reach.

## 1. OpenAI and Jev clients never log the API key

- **Precondition:** `internal/llm.NewOpenAI(cfg, httpClient)` and
  `internal/jev.NewClient(cfg, httpClient)` as specified take no logger
  parameter, so there is no injectable sink to assert against in a black-box
  test. `go vet`/`golangci-lint` (gosec) catch accidental `%v`-formatting of a
  struct containing the key, but not a deliberate `log.Printf("key=%s", cfg.APIKey)`.
- **Steps:** Code review `internal/llm/openai.go` and `internal/jev/jev.go`:
  confirm `cfg.APIKey` is used only to build the `Authorization` header, and
  that no `log`, `slog`, `fmt.Print*`, or error-wrapping path includes it or
  the full `Authorization` header value.
- **Expected result:** No log line, error message, or panic value contains the
  API key in any code path, including error paths for non-2xx responses.
- **Why manual:** no logger is part of the specified constructor signature for
  either client, so there is no way to capture "nothing was logged" as an
  assertion; this is a code-review property, not an observable one.

## 2. CI workflow execution on GitHub-hosted runners

- **Precondition:** `.github/workflows/ci.yml` committed; a GitHub repository
  with Actions enabled.
- **Steps:** push a commit; observe the `build`, `golangci-lint`, `actionlint`,
  and `benchmark` jobs run and the Markdown summaries/artifacts appear.
- **Expected result:** all jobs succeed; the benchmark job's `compare` gate
  fails the build if hardened is not significantly better than vulnerable or
  regresses against `benchmarks/baseline-hardened.json`.
- **Why manual:** explicitly out of scope per the test brief ("GitHub-hosted
  CI behaviour"). The underlying commands (`run`, `compare`,
  `validate-judges`) are exercised directly by
  `internal/cli/cli_test.go` and `cmd/injectionbench/e2e_test.go`; only the
  GitHub Actions runner environment itself is unverified here.

## 3. README content quality (acceptance criterion 10)

- **Precondition:** `README.md` committed.
- **Steps:** read the README and confirm it covers, in English: defences,
  attack categories with OWASP/ATLAS mapping, statistics methodology, judge
  validation results, the target HTTP contract, a results table from an
  actually-run command, and limitations.
- **Expected result:** every topic is present and accurate.
- **Why manual:** this is a prose-quality/completeness review, not a
  machine-checkable assertion.
