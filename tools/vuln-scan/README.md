# vuln-scan

A lightweight vulnerability scanner for this repository. It runs locally and in CI, writes
`scan-results.json` and `scan-summary.md`, and can post the top finding to Slack in a format
the Grok Bot can pick up and remediate.

It only detects issues and suggests fixes. It never changes application code and contains no
exploit code.

> **Demo finding (revert before relying on results):** `sample/VulnDemo/VulnDemo.csproj` pins
> `Newtonsoft.Json` **12.0.3**, which is affected by
> [GHSA-5crp-9r3c-p9vr](https://github.com/advisories/GHSA-5crp-9r3c-p9vr) (CVE-2024-21907, high,
> fixed in 13.0.1). The project is not part of `NopCommerce.sln` and nothing references it. It
> exists only so there is a known, real finding to demo against. **To revert, delete
> `tools/vuln-scan/sample/`** and remove `tools/vuln-scan/sample` from `DEFAULT_CODE_PATHS` in
> `scan.py`.

## What it checks

| Check | How | Findings |
| --- | --- | --- |
| Vulnerable NuGet packages | Parses every `.csproj` / `Directory.Packages.props`, runs `dotnet list package --vulnerable --include-transitive --format json` on `src/NopCommerce.sln` plus any project not in the solution, then looks up the fixed version for each advisory in the GitHub Advisory Database | One finding per vulnerable package version, with every advisory ID, its severity and fixed version, and the affected projects. The location is where the fix belongs: the `PackageReference` line, or for transitive packages the lowest project in the reference graph, along with the direct package that pulls it in |
| SQL from request input (`rules/sql-injection.yml`) | Semgrep taint rule: string action parameters / `Request.Query|Form|Headers|Cookies` reaching `SqlCommand`, `CommandText`, `FromSqlRaw`, `ExecuteSqlRaw`, linq2db / `INopDataProvider` query methods | high |
| SQL built by concatenation (`rules/sql-injection.yml`) | Semgrep: the same sinks called with `"..." + x`, `$"...{x}"` or `string.Format` | medium |
| Missing antiforgery token (`vulnscan/antiforgery.py`) | `[HttpPost/Put/Patch/Delete]` actions where neither the action nor any class in the inheritance chain has `[ValidateAntiForgeryToken]` / `[AutoValidateAntiforgeryToken]` | medium |
| Hardcoded secrets (`rules/hardcoded-secrets.yml`) | Well-known token formats (AWS, Slack, GitHub, Stripe, Google, private keys), credential-named fields assigned high-entropy literals, connection strings with inline passwords | critical / high |
| Unsafe deserialization (`rules/unsafe-deserialization.yml`) | `BinaryFormatter`-family formatters, Json.NET `TypeNameHandling` other than `None`, `JavaScriptSerializer` + `SimpleTypeResolver` | high |

### Keeping false positives low

- The antiforgery check is implemented in Python rather than Semgrep. nopCommerce applies
  `[AutoValidateAntiforgeryToken]` on base controllers such as `BaseAdminController`, and
  Semgrep only sees one file at a time. The check indexes every controller across the tree,
  merges `partial` classes and resolves inheritance before flagging an action. It skips
  `[IgnoreAntiforgeryToken]` (an explicit opt-out), `[ApiController]`, `*WebhookController`
  (server-to-server callbacks) and the whole check if a global antiforgery filter is registered.
- `sql-string-concatenation` excludes `Nop.Data/DataProviders/**`. That code interpolates table
  and sequence names from mapped entity metadata into maintenance DDL (`RESEED`, `VACUUM`,
  `OPTIMIZE`), and identifiers cannot be parameterized.
- Generic method names (`Execute`, `Query`, ...) only count as SQL sinks on a receiver that
  looks like a DB connection, data provider or context.
- `src/Tests` is excluded by default (test data contains sample passwords and SQL).
- Every rule has a fixture (`rules/*.cs`) with `// ruleid:` and `// ok:` cases. Run
  `semgrep --test tools/vuln-scan/rules`.

## Running it

Requirements: the .NET SDK from `global.json`, Python 3.10+, and Semgrep.

```bash
pip install -r tools/vuln-scan/requirements.txt
python tools/vuln-scan/scan.py                     # writes scan-results.json + scan-summary.md
python tools/vuln-scan/scan.py --skip-deps         # code rules only (no dotnet needed)
python tools/vuln-scan/scan.py --offline           # don't query GitHub for fixed versions
python tools/vuln-scan/scan.py --fail-on high      # exit 1 on high/critical findings
python tools/vuln-scan/gate.py scan-results.json --fail-on high
```

Set `GITHUB_TOKEN` to avoid the unauthenticated GitHub API rate limit for advisory lookups.
A full run on this repo takes about a minute after `dotnet restore`.

### Output

`scan-results.json` (sorted most severe first):

```json
{
  "schema_version": 1,
  "scanned_at": "2026-11-24T21:05:12Z",
  "commit": "9cdf7a5fc7",
  "errors": [],
  "stats": {"projects_discovered": 41, "dependency_targets": 3, "semgrep_files_scanned": 4920},
  "summary": {"total": 11, "by_severity": {"critical": 1, "high": 6, "medium": 4, "low": 0, "info": 0}},
  "findings": [
    {
      "id": "VS-…",
      "title": "System.Drawing.Common 4.7.0 is affected by GHSA-rxg9-xrhp-64gj (...)",
      "severity": "critical",
      "file": "src/Libraries/Nop.Services/Nop.Services.csproj",
      "line": 23,
      "rule": "dependency/vulnerable-package",
      "fix_hint": "Transitive dependency (pulled in by PdfRpt.Core). Pin <PackageReference ... Version=\"4.7.2\" /> ...",
      "category": "dependency",
      "why": "...",
      "details": {"advisories": [{"id": "GHSA-…", "severity": "critical", "fixed_version": "4.7.2"}], "affected_projects": ["..."]}
    }
  ]
}
```

`id` is a stable hash of the rule and location, so the same finding keeps its id across runs.

## Slack

```bash
export SLACK_CHANNEL="#security-findings"
export SLACK_WEBHOOK_URL=...                       # from a secret store; never commit or echo it
python tools/vuln-scan/post_slack.py scan-results.json --dry-run   # preview, sends nothing
python tools/vuln-scan/post_slack.py scan-results.json             # post the top finding
python tools/vuln-scan/post_slack.py --min-severity high           # only post high/critical
```

The webhook is read from the environment only. It must be an `https://hooks.slack.com/` URL,
and it is never printed, including in error messages. Message format:

~~~
:rotating_light: *CRITICAL*: <title>
`<file>:<line>`
Why it matters: <one line>
Fix hint: <fix hint>
```{"id":"VS-…","rule":"…","severity":"critical","file":"…","line":23,"fix_hint":"…"}```
@ the bot to remediate
~~~

The fenced JSON line carries the machine-readable fields the bot needs. Slack escapes `&`, `<`
and `>` as `&amp;`, `&lt;` and `&gt;`, so decode those before parsing.

## CI

`.github/workflows/vuln-scan.yml` runs on pull requests to `main` and `develop`, nightly at
03:00 UTC, and on manual dispatch. It runs the unit tests and rule tests, then the scan, and
publishes `scan-summary.md` to the job summary and both files as the `vuln-scan-results`
artifact.

- **Pull requests:** fail only if there are high or critical findings (`gate.py --fail-on high`).
  Medium and low findings are reported but don't block.
- **Nightly / manual:** post the top finding to Slack when the `SLACK_WEBHOOK_URL` secret and
  the `SLACK_CHANNEL` repository variable are configured. These runs never fail on findings.

## Tests

```bash
python -m unittest discover -s tools/vuln-scan/tests   # parsers, Slack formatter, gate, antiforgery
semgrep --test tools/vuln-scan/rules                   # rule fixtures
```

## Layout

```
scan.py            entry point: runs all checks, writes JSON + markdown
gate.py            CI gate on severity
post_slack.py      posts the top finding (or --dry-run preview)
vulnscan/          projects.py (csproj/props/sln parser), deps.py, advisories.py,
                   code.py (Semgrep runner), antiforgery.py, report.py, slack.py
rules/             Semgrep rules + test fixtures
sample/            DEMO ONLY: seeded vulnerable package (see top of this file)
tests/             unit tests
```
