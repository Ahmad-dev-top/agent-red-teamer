# Continuous red-teaming in CI

Run the attack campaign on every push/PR and **fail the build when the agent
breaches**. This is the retainer tier as code: every model swap, prompt change,
or tool addition is re-tested before it ships.

## The command

```bash
redforge-agents ci <target.yaml> \
  --adapter stub \            # stub (offline demo) | http (real endpoint)
  --fail-on high \            # info | low | medium | high | critical
  --json reports/ci-report.json \
  --summary "$GITHUB_STEP_SUMMARY"
```

It runs the scan, writes a JSON report, prints (and optionally appends) a
markdown summary, and **exits non-zero when the gate fails** — which is what
turns it into a build check.

- `--fail-on` — the severity at or above which a finding fails the build.
- `--json` — machine-readable report (uploaded as a CI artifact).
- `--summary` — a file to append the markdown verdict to; point it at
  `$GITHUB_STEP_SUMMARY` and the result shows up on the run/PR.

## Two gating modes

**Threshold (default).** Any finding at or above `--fail-on` fails the build.
Use this for a target that should have *no* breaches.

**Baseline / regression.** Pass a prior report and only *new* findings fail:

```bash
redforge-agents ci <target.yaml> --baseline reports/baseline.json --fail-on medium ...
```

Commit `reports/baseline.json` after a reviewed scan. The build then blocks any
**new** break a change introduces, while a known, risk-accepted finding won't
break every build. Refresh the baseline when you consciously accept a finding.

## GitHub Actions

`.github/workflows/redforge-scan.yml` ships ready to run. Out of the box it scans
the demo target with the stub adapter, so it's green immediately and uploads the
report artifact. To scan a real agent:

1. Set the target's `config.url` (or use a dedicated CI target file) and switch
   to `--adapter http`.
2. Put any credentials in **GitHub Actions secrets**, referenced as env vars —
   never in the workflow or the repo. Test a staging/sandbox copy, never
   production.
3. Optionally commit a `reports/baseline.json` and add `--baseline` to gate on
   regressions only.

## Exit codes

| code | meaning |
|---|--:|
| `0` | gate passed — no breaching findings above threshold (or none new vs baseline) |
| `1` | gate failed — a breach at or above `--fail-on` (or a new one vs baseline) |

The scan itself still decides success the same way everywhere: the deterministic
judge, from hard evidence. CI only grades the resulting report against your
policy.
